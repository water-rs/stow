import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { setTimeout } from "node:timers/promises";

const root = await mkdtemp(path.join(os.tmpdir(), "stow-cpu-runtime-"));
const readyFile = path.join(root, "ready.json");
const child = spawn(process.execPath, [
	path.resolve(import.meta.dirname, "cpu-runtime.mjs"),
	"--config", path.resolve(import.meta.dirname, "../../.skyzen/gen/wrangler.toml"),
	"--port", "0", "--inspector-port", "0", "--persist-to", path.join(root, "state"),
	"--ready-file", readyFile,
], { stdio: "inherit", detached: true });
let exited = false;
const exit = new Promise((resolve, reject) => {
	child.once("error", reject);
	child.once("exit", (code, signal) => { exited = true; resolve({ code, signal }); });
});
try {
	const deadline = Date.now() + 30_000;
	let ready;
	while (Date.now() < deadline) {
		assert(!exited, "CPU runtime exited before reporting readiness");
		try { ready = JSON.parse(await readFile(readyFile, "utf8")); break; }
		catch (error) { if (error.code !== "ENOENT") throw error; }
		await setTimeout(25);
	}
	assert(ready, "CPU runtime did not become ready within 30 seconds");
	assert(ready.modules.some((module) => module.path === ready.main), "deployment entrypoint must be registered");
	for (const module of ready.modules) {
		const relative = path.relative(ready.modulesRoot, module.path);
		assert(relative && !relative.startsWith("..") && !path.isAbsolute(relative),
			`module must come from Wrangler's deployment output: ${module.path}`);
	}
	const response = await fetch(new URL("/", ready.url), { signal: AbortSignal.timeout(5_000) });
	assert.equal(response.status, 200, await response.text());
	const inspector = new URL(ready.inspector);
	assert.equal(inspector.protocol, "ws:");
	assert(inspector.pathname.includes("stow-edge-mock"), "Inspector must name the edge, not egress");
} finally {
	if (!exited) process.kill(-child.pid, "SIGTERM");
	const result = await Promise.race([exit, setTimeout(5_000, undefined)]);
	if (!result && !exited) { process.kill(-child.pid, "SIGKILL"); await exit; }
	await rm(root, { recursive: true, force: true });
}
