// stow#1100 — the edge's Cron Trigger drives the periodic workflows.
//
// The real workerd build (`skyzen build --provider cloudflare --manifest
// edge/Skyzen.mock.toml`) receives scheduled events carrying the cron
// expressions the mock manifest declares; the scheduled handler must
// dispatch exactly the workflows `STOW_PERIODIC_WORKFLOWS` names for that
// cron, through the scheduler object to the local-CI stub
// (vitest.config.ts). The failure paths (a refused dispatch, an unnamed
// cron) reject the invocation, which workerd also reports as an uncaught
// exception that vitest counts against the whole run, so they are covered
// by the host tests of `edge/src/periodic.rs` instead.

import { env, runInDurableObject } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

const CI = "http://127.0.0.1:28124/__control/periodic";

async function reset() {
	const cleared = await fetch(CI, { method: "POST", body: JSON.stringify({}) });
	expect(cleared.status).toBe(204);
	const stub = env.SCHEDULER.get(env.SCHEDULER.idFromName("scheduler"));
	const response = await stub.fetch("https://scheduler.invalid/reset", {
		method: "POST",
		headers: { "x-stow-actor": "scheduled-test" },
	});
	expect(response.status, await response.text()).toBe(200);
}

// The stub only answers the Worker under test (outboundService), so the
// control calls go through the same outbound path as the edge's own.
async function dispatched(): Promise<string[]> {
	return (await fetch(CI)).json();
}

describe("scheduled handler", () => {
	const schedule = JSON.parse(
		(env as unknown as Record<string, string>).STOW_PERIODIC_WORKFLOWS,
	) as Record<string, (string | { workflow: string; ref: string })[]>;
	// A bare name dispatches on main; an object names its ref (the local-CI
	// stub records only the workflow stem, so the ref is pinned by the host
	// tests of types/src/periodic.rs and types/src/ci.rs).
	const file = (entry: string | { workflow: string }) =>
		typeof entry === "string" ? entry : entry.workflow;

	it("dispatches exactly the workflows due for each cron", async () => {
		for (const [cron, workflows] of Object.entries(schedule)) {
			await reset();
			await exports.default.scheduled({ cron, scheduledTime: Date.now() });
			expect((await dispatched()).sort()).toEqual(
				workflows.map((entry) => file(entry).replace(/\.ya?ml$/, "")).sort(),
			);
		}
	});
});


describe("control dispatch recovery fence", () => {
	beforeEach(reset);
	it.each(["primary", "secondary"])("shares a %s recovery deadline across control entry points", async (mode) => {
		const control = "http://127.0.0.1:28124/__control/ci-limit";
		const configured = await fetch(control, { method: "POST", body: JSON.stringify({ mode }) });
		expect(configured.status).toBe(204);
		const stub = env.SCHEDULER.get(env.SCHEDULER.idFromName("scheduler"));
		const call = async (route: string, body: unknown) => {
			const response = await stub.fetch(`https://scheduler.invalid${route}`, {
				method: "POST", headers: { "content-type": "application/json" },
				body: JSON.stringify(body),
			});
			await response.arrayBuffer();
			return response.status;
		};
		const periodic = { workflow: "watchdog.yml", ref: "main" };
		const release = { rustc_version: "1.99.1" };
		const first = mode === "primary" ? "/periodic/dispatch" : "/preheat/release";
		expect(await call(first, mode === "primary" ? periodic : release)).toBe(502);
		expect(await call("/periodic/dispatch", periodic)).toBe(503);
		expect(await call("/preheat/release", release)).toBe(503);
		const observed = await (await fetch(control)).json() as { attempts: number };
		expect(observed.attempts).toBe(1);
		const deadlines = await runInDurableObject(stub, async (_instance, ctx) => {
			return ctx.storage.sql.exec<{ until: number }>(
				"SELECT json_extract(event, '$.until') AS until FROM event_log WHERE json_extract(event, '$.event') = 'ci_rate_limited'",
			).toArray();
		});
		expect(deadlines).toHaveLength(1);
		expect(deadlines[0].until).toBeGreaterThan(Date.now());
	});
});

describe("scheduler activity ledger", () => {
	beforeEach(reset);

	it("counts outbound CI waiting and excludes time between invocations", async () => {
		const stub = env.SCHEDULER.get(env.SCHEDULER.idFromName("scheduler"));
		const active = async () => {
			const response = await stub.fetch("https://scheduler.invalid/budget/ledger");
			expect(response.status).toBe(200);
			return ((await response.json()) as { active_ms: number }).active_ms;
		};
		const latency = 250;
		const configured = await fetch("http://127.0.0.1:28124/__control/ci-latency", {
			method: "POST",
			body: JSON.stringify({ milliseconds: latency }),
		});
		expect(configured.status).toBe(204);
		const before = await active();
		const response = await stub.fetch("https://scheduler.invalid/periodic/dispatch", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ workflow: "watchdog.yml", ref: "main" }),
		});
		expect(response.status, await response.text()).toBe(200);
		const after = await active();
		expect(after - before).toBeGreaterThanOrEqual(latency);
		await new Promise((resolve) => setTimeout(resolve, latency));
		const idle = await active();
		// A ledger read has its own handler cost, but the preceding idle
		// interval must not be charged as another outbound wait.
		expect(idle - after).toBeLessThan(latency / 2);
	});
});
