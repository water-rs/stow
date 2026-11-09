import { createRequire } from "node:module";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";
import { externalBindings, outboundModules } from "./external-data.mjs";

const require = createRequire(import.meta.url);
const { unstable_getMiniflareWorkerOptions, unstable_readConfig } = require("wrangler");
// Use precisely the Miniflare version Wrangler's locked API targets.
const wranglerRequire = createRequire(require.resolve("wrangler"));
const { Miniflare, convertV4MiniflareOptions } = wranglerRequire("miniflare");
const { values } = parseArgs({ options: {
	config: { type: "string" },
	port: { type: "string" },
	"inspector-port": { type: "string" },
	"persist-to": { type: "string" },
	"inspector-url-file": { type: "string" },
	var: { type: "string", multiple: true, default: [] },
} });
for (const name of ["config", "port", "inspector-port", "persist-to", "inspector-url-file"]) {
	if (!values[name]) throw new Error(`missing --${name}`);
}
const config = unstable_readConfig({ config: path.resolve(values.config) });
const { workerOptions, main, externalWorkers, define } = unstable_getMiniflareWorkerOptions(config);
if (!config.name) throw new Error("generated Worker configuration has no name");
if (!main) throw new Error("generated Worker configuration has no main module");
if (Object.keys(define).length) throw new Error("CPU runtime needs a built artifact without compile-time defines");
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
		{ ...workerOptions, name: config.name, modules: true, scriptPath: main, bindings,
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
	await miniflare.ready;
	const listing = await miniflare.getInspectorURL();
	listing.protocol = "http:";
	listing.pathname = "/json";
	const response = await fetch(listing, { signal: AbortSignal.timeout(5_000) });
	if (!response.ok) throw new Error(`Inspector listing: HTTP ${response.status}`);
	const targets = (await response.json()).filter((target) => target.id === `core:user:${config.name}`);
	if (targets.length !== 1) throw new Error(`Inspector has ${targets.length} targets for ${config.name}`);
	await writeFile(values["inspector-url-file"], targets[0].webSocketDebuggerUrl + "\n");
	console.info("CPU runtime ready", JSON.stringify({
		main, inspector: targets[0].webSocketDebuggerUrl,
	}));
	await stopped;
} finally {
	await miniflare.dispose();
}
