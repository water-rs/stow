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

import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

const CI = "http://127.0.0.1:28124/__control/periodic";

async function reset() {
	await fetch(CI, { method: "POST", body: JSON.stringify({}) });
}

// The stub only answers the Worker under test (outboundService), so the
// control calls go through the same outbound path as the edge's own.
async function dispatched(): Promise<string[]> {
	return (await fetch(CI)).json();
}

describe("scheduled handler", () => {
	const schedule = JSON.parse(
		(env as unknown as Record<string, string>).STOW_PERIODIC_WORKFLOWS,
	) as Record<string, string[]>;

	it("dispatches exactly the workflows due for each cron", async () => {
		for (const [cron, workflows] of Object.entries(schedule)) {
			await reset();
			await exports.default.scheduled({ cron, scheduledTime: Date.now() });
			expect((await dispatched()).sort()).toEqual(
				workflows.map((file) => file.replace(/\.ya?ml$/, "")).sort(),
			);
		}
	});
});
