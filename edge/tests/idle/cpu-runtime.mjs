import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";
import { externalBindings, outboundModules } from "./external-data.mjs";

const require = createRequire(import.meta.url);
const { unstable_getMiniflareWorkerOptions, unstable_readConfig } = require("wrangler");
// Use precisely the Miniflare version Wrangler's locked API targets.
const wranglerRequire = createRequire(require.resolve("wrangler"));
const { Miniflare, compileModuleRules, convertV4MiniflareOptions, testRegExps } = wranglerRequire("miniflare");
const { values } = parseArgs({ options: {
	config: { type: "string" },
	port: { type: "string" },
	"inspector-port": { type: "string" },
	"persist-to": { type: "string" },
	"ready-file": { type: "string" },
	var: { type: "string", multiple: true, default: [] },
} });
for (const name of ["config", "port", "inspector-port", "persist-to", "ready-file"]) {
	if (!values[name]) throw new Error(`missing --${name}`);
}
const config = unstable_readConfig({ config: path.resolve(values.config) });
const { workerOptions, main, externalWorkers, define } = unstable_getMiniflareWorkerOptions(config);
if (!config.name) throw new Error("generated Worker configuration has no name");
if (!main) throw new Error("generated Worker configuration has no main module");
if (Object.keys(define).length) throw new Error("CPU runtime needs a built artifact without compile-time defines");
// Build the deployment module graph before adapting it to v5's manifest.
// Scanning the source directory also registers unrelated tests and dependencies.
const { modulesRules, ...runtimeOptions } = workerOptions;
await mkdir(path.resolve(values["persist-to"]), { recursive: true });
const modulesRoot = await mkdtemp(path.join(path.resolve(values["persist-to"]), "bundle-"));
const wranglerBin = path.resolve(path.dirname(require.resolve("wrangler")), "../bin/wrangler.js");
const build = spawn(process.execPath, [wranglerBin, "deploy", "--dry-run",
	"--config", path.resolve(values.config), "--outdir", modulesRoot],
	{ stdio: "inherit", detached: true, env: { ...process.env, WRANGLER_SEND_METRICS: "false" } });
const buildDeadline = setTimeout(() => process.kill(-build.pid, "SIGKILL"), 30_000);
try {
	await new Promise((resolve, reject) => {
		build.once("error", reject);
		build.once("exit", (code, signal) => code === 0 ? resolve()
			: reject(new Error(`Wrangler dry run failed: code ${code}, signal ${signal}`)));
	});
} catch (error) {
	await rm(modulesRoot, { recursive: true, force: true });
	throw error;
} finally {
	clearTimeout(buildDeadline);
}
const builtMain = path.join(modulesRoot, config.no_bundle ? path.basename(main) : `${path.parse(main).name}.js`);
const rules = compileModuleRules([
	...modulesRules,
	{ type: "ESModule", include: ["**/*.js", "**/*.mjs"] },
	{ type: "CommonJS", include: ["**/*.cjs"] },
]);
const modules = [{ type: "ESModule", path: builtMain }];
for (const file of (await readdir(modulesRoot, { recursive: true, withFileTypes: true }))
	.filter((entry) => entry.isFile())
	.map((entry) => path.join(entry.parentPath, entry.name)).sort()) {
	if (file === builtMain) continue;
	const relative = path.relative(modulesRoot, file).split(path.sep).join("/");
	const rule = rules.find(({ include }) => testRegExps(include, relative));
	if (rule) modules.push({ type: rule.type, path: file });
}
const bindings = { ...workerOptions.bindings };
for (const entry of values.var) {
	const colon = entry.indexOf(":");
	if (colon < 1) throw new Error(`malformed --var ${entry}`);
	bindings[entry.slice(0, colon)] = entry.slice(colon + 1);
}
const origins = ["STOW_LOCAL_CI_URL", "GHCR_BASE_URL", "STOW_GITHUB_API_URL", "STOW_STATS_SQL_URL"]
	.map((name) => {
		const url = new URL(bindings[name]);
		if (url.hostname !== "127.0.0.1") throw new Error(`${name} is not a mock loopback URL`);
		return url.origin;
	});
const miniflare = new Miniflare(convertV4MiniflareOptions({
	host: "127.0.0.1",
	port: Number(values.port),
	inspectorPort: Number(values["inspector-port"]),
	resourcePersistencePath: path.resolve(values["persist-to"]),
	workers: [
		{ ...runtimeOptions, name: config.name, modules, modulesRoot, bindings,
			outboundService: "cpu-egress", unsafeInspectorProxy: false },
		...externalWorkers,
		{
			name: "cpu-egress",
			modules: outboundModules("cpu-egress.mjs"),
			modulesRoot: import.meta.dirname,
			compatibilityDate: workerOptions.compatibilityDate,
			unsafeInspectorProxy: false,
			bindings: { ...await externalBindings(), LOOPBACK_ORIGINS: JSON.stringify([...new Set(origins)]) },
		},
	],
}));
try {
	const stopped = new Promise((resolve) => {
		process.once("SIGTERM", resolve);
		process.once("SIGINT", resolve);
	});
	const url = String(await miniflare.ready);
	const listing = await miniflare.getInspectorURL();
	listing.protocol = "http:";
	listing.pathname = "/json";
	const response = await fetch(listing, { signal: AbortSignal.timeout(5_000) });
	if (!response.ok) throw new Error(`Inspector listing: HTTP ${response.status}`);
	const targets = (await response.json()).filter((target) => target.id === `core:user:${config.name}`);
	if (targets.length !== 1) throw new Error(`Inspector has ${targets.length} targets for ${config.name}`);
	const ready = { main: builtMain, modulesRoot, modules, url, inspector: targets[0].webSocketDebuggerUrl };
	const temporary = values["ready-file"] + ".pending";
	await writeFile(temporary, JSON.stringify(ready));
	await rename(temporary, values["ready-file"]);
	console.info("CPU runtime ready", JSON.stringify(ready));
	await stopped;
} finally {
	await miniflare.dispose();
	await rm(modulesRoot, { recursive: true, force: true });
}
