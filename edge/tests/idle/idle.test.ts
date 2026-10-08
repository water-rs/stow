// stow#593 — the native idle proof for the scheduler Durable Object.
//
// The Rust `alarm pass (idle)` drive prices a paused pass with in-flight
// fixture work; it cannot prove an empty scheduler stops waking. This
// suite runs the real workerd build (`edge/.skyzen/gen`, emitted by
// skyzen's cloudflare bundle) under @cloudflare/vitest-plugin:
// storage is isolated per test, alarms are armed and executed natively
// through `runDurableObjectAlarm`, and `storage.getAlarm()` is read back
// outside the alarm callback — inside a running callback it reports
// `null` unless the handler itself re-armed, which would make the
// assertion meaningless.
//
// The scheduler is initialized only through its operator `/migrate`
// route — the same route `deploy-edge.yml`/`stow-admin scheduler
// migrate` invoke. No public probing endpoint and no production debug
// code is added: inspection goes through `runInDurableObject` on the
// real instance, and every outbound fetch routes through the
// `dispatch-stub` outbound service (see vitest.config.ts), which only
// answers `<STOW_LOCAL_CI_URL>/dispatch` and 500s the rest — an egress
// this suite does not expect poisons the row under test.
//
// No-work audit: nothing in the idle path is a timer, a detached
// promise, `waitUntil` work or an open connection. `runDurableObjectAlarm`
// returns after the alarm's awaited work completes; the assertions below
// then require the storage-visible contract — `getAlarm() === null` and a
// second invocation reporting `false` — plus zero queue-state change and
// zero stray-egress effects. Hidden wakefulness is audited statically:
// `grep -R "waitUntil\|setTimeout\|setInterval" edge/src edge/stable-worker.js`
// finds ZERO call sites in the whole edge runtime — the DO alarm is the
// only mechanism that can re-wake the scheduler, and these tests prove
// it is deleted.

import {
	applyD1Migrations,
	env,
	runDurableObjectAlarm,
	runInDurableObject,
} from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

const TARGET = "x86_64-unknown-linux-gnu";
const RUSTC = "1.98.1";
const DO = "https://scheduler.invalid";
const STALE_LEASE_MS = 10 * 60 * 1000; // STOW_STALE_DISPATCH_MINUTES="10"

type Env2 = typeof env & Record<string, string>;

function enqueue(name: string, depends_on: unknown[] = [], downloads = 100) {
	return {
		crate_name: name,
		version: "1.0.0",
		features_json: '["default"]',
		target: TARGET,
		rustc_version: RUSTC,
		downloads,
		source: "CacheMiss",
		depends_on,
		host_side: false,
		preserve_lockfile: false,
	};
}

function depOn(task: {
	crate_name: string;
	version: string;
	features_json: string;
	target: string;
	rustc_version: string;
}) {
	return {
		crate_name: task.crate_name,
		version: task.version,
		features_json: task.features_json,
		target: task.target,
		rustc_version: task.rustc_version,
		host_side: false,
	};
}

async function freshStub() {
	const id = env.SCHEDULER.newUniqueId();
	return env.SCHEDULER.get(id);
}

async function migrate(stub: DurableObjectStub) {
	// Operator route only — the one place DDL may issue.
	const res = await stub.fetch(`${DO}/migrate`, { method: "POST" });
	expect(res.status).toBe(200);
	return res.json();
}

async function submit(stub: DurableObjectStub, requests: unknown[]) {
	const res = await stub.fetch(`${DO}/tasks/submit`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(requests),
	});
	return { status: res.status, body: await res.json() };
}

async function submitTrusted(stub: DurableObjectStub, requests: unknown[]) {
	const res = await stub.fetch(`${DO}/tasks/submit/trusted`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(requests),
	});
	return { status: res.status, body: await res.json() };
}

async function tasks(stub: DurableObjectStub) {
	const res = await stub.fetch(`${DO}/tasks?limit=200`);
	expect(res.status).toBe(200);
	return (await res.json()) as {
		task_id: string;
		status: string;
		crate_name: string;
		version: string;
		features_json: string;
		target: string;
		rustc_version: string;
	}[];
}

// `storage.getAlarm()` read outside any alarm callback.
async function getAlarm(stub: DurableObjectStub) {
	return runInDurableObject(stub, async (_instance, ctx) => {
		return await ctx.storage.getAlarm();
	});
}

// A genuine future native alarm — what a live scheduler leaves behind.
async function arm(stub: DurableObjectStub, ms = 60_000) {
	await runInDurableObject(stub, async (_instance, ctx) => {
		await ctx.storage.setAlarm(Date.now() + ms);
	});
	expect(await getAlarm(stub)).not.toBeNull();
}

// Rows by status, read through the DO's real storage.
async function statusCounts(stub: DurableObjectStub) {
	return runInDurableObject(stub, async (_instance, ctx) => {
		const rows = ctx.storage.sql
			.exec("SELECT status, COUNT(*) AS n FROM queue GROUP BY status")
			.toArray() as { status: string; n: number }[];
		return Object.fromEntries(rows.map((r) => [r.status, r.n]));
	});
}

beforeAll(async () => {
	await applyD1Migrations(env.STOW_DB, env.TEST_MIGRATIONS as never);
});

// A submit whose rows are immediately eligible arms a real alarm at
// ~now, and workerd fires it on its own — so the dispatch cannot be
// synchronized on `runDurableObjectAlarm` (it correctly reports `false`
// when the alarm already ran). Wait for the row the live alarm claimed.
async function waitForStatus(stub: DurableObjectStub, wanted: string) {
	for (let i = 0; i < 80; i++) {
		const rows = await tasks(stub);
		if (rows.some((r) => r.status === wanted)) return rows;
		await new Promise((r) => setTimeout(r, 25));
	}
	throw new Error(`no row reached status ${wanted}`);
}

// The full idle contract for a queue that has nothing to do. Two
// layers, in order:
//
//   1. Natural state — whatever alarm the real event (migrate, submit,
//      complete-run, freeze) left armed. If one is armed, it must run
//      exactly once and leave nothing behind: `getAlarm() === null`
//      afterwards and a second invocation `false`. A re-arm chain fails
//      here, before any probe touches the instance. If nothing is
//      armed, the event itself was already quiet.
//   2. Probe — a genuine future native alarm (`setAlarm` inside
//      `runInDurableObject`) proves the handler deletes rather than
//      reschedules: the armed probe runs (`true`), `getAlarm()` reads
//      `null` outside the completed callback, and a second invocation
//      returns `false`.
//
// Both end with the queue-state assertion: no row was claimed, failed
// or touched by stray egress across either pass.
async function expectQuiescent(
	stub: DurableObjectStub,
	before: Record<string, number>,
) {
	const natural = await getAlarm(stub);
	if (natural !== null) {
		// The event left a wake — it must be a single shot that deletes
		// itself, not a re-arm chain.
		expect(await runDurableObjectAlarm(stub)).toBe(true);
		expect(await getAlarm(stub)).toBeNull();
		expect(await runDurableObjectAlarm(stub)).toBe(false);
		expect(await statusCounts(stub)).toEqual(before);
	}
	await arm(stub);
	expect(await runDurableObjectAlarm(stub)).toBe(true);
	// getAlarm outside the completed alarm callback: the handler armed
	// no next wake — the scheduler stopped waking.
	expect(await getAlarm(stub)).toBeNull();
	expect(await runDurableObjectAlarm(stub)).toBe(false);
	expect(await statusCounts(stub)).toEqual(before);
}

describe("scheduler idle proof (stow#593)", () => {
	it("empty scheduler: an armed alarm is deleted and never rescheduled", async () => {
		const stub = await freshStub();
		const report = await migrate(stub);
		expect(report).toBeTruthy();
		await expectQuiescent(stub, {});
	});

	it("completed work: a drained queue also stops waking", async () => {
		const stub = await freshStub();
		await migrate(stub);
		const { status, body } = await submit(stub, [enqueue("idle-done")]);
		expect(status).toBe(200);
		expect(body.inserted).toBe(1);

		// Submit armed a real alarm; it fired on workerd's schedule and
		// claimed the task against the dispatch stub — the only fetch the
		// egress gate permits — then the same route the webhook drives
		// completes it.
		const rows = await waitForStatus(stub, "dispatched");
		const task = rows.find((r) => r.status === "dispatched")!;

		const res = await stub.fetch(`${DO}/tasks/complete-run`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				task_id: task.task_id,
				success: true,
				error: "",
				github_run_id: "4242",
			}),
		});
		expect(res.status).toBe(200);
		const after = await statusCounts(stub);
		expect(after).toEqual({ completed: 1 });

		await expectQuiescent(stub, after);
	});

	it("positive control: an in-flight lease keeps the alarm armed", async () => {
		const stub = await freshStub();
		await migrate(stub);
		const { status } = await submit(stub, [enqueue("idle-inflight")]);
		expect(status).toBe(200);

		await waitForStatus(stub, "dispatched");
		const counts = await statusCounts(stub);
		expect(counts.dispatched ?? counts.running).toBe(1);

		// The dispatched row's lease expiry keeps a wake armed — a
		// disconnected or no-op instance cannot pass this check.
		const armed = await getAlarm(stub);
		expect(armed).not.toBeNull();
		// The lease is `updated_at + STOW_STALE_DISPATCH_MINUTES` — now + 10m
		// within a generous tolerance for test clock skew.
		expect(Math.abs((armed as number) - (Date.now() + STALE_LEASE_MS))).toBeLessThan(
			60_000,
		);
		// A second native alarm still runs (the wake exists) and the
		// in-flight row stays dispatched — nothing silently drained.
		expect(await runDurableObjectAlarm(stub)).toBe(true);
		expect(await getAlarm(stub)).not.toBeNull();
		expect(await statusCounts(stub)).toEqual(counts);
	});

	it("dependency-gated queue: unmet deps arm nothing and never spin", async () => {
		const stub = await freshStub();
		// The parent must exist as a queue row (an unresolvable dep is
		// dropped at canonicalization, not gated) yet never be dispatchable
		// itself — otherwise the alarm legitimately keeps waking on its
		// in-flight lease. The stamped floor holds it ineligible.
		(env as Env2).STOW_MIN_DISPATCH_VALUE = "1000000";
		try {
			await migrate(stub);
			const { status: s1 } = await submit(stub, [
				enqueue("idle-dep-parent", [], 1),
			]);
			expect(s1).toBe(200);
			const [parent] = await tasks(stub);
			// The dependent is eligible by value but `deps_met = 0` while
			// the parent is unpublished — a wake on it would make no
			// progress, so the queue must never arm for it.
			const { status: s2, body } = await submit(stub, [
				enqueue("idle-dep-child", [depOn(parent)]),
			]);
			expect(s2).toBe(200);
			expect(body.inserted).toBe(1);
			expect(await getAlarm(stub)).toBeNull();
			await expectQuiescent(stub, { pending: 2 });
		} finally {
			delete (env as Env2).STOW_MIN_DISPATCH_VALUE;
		}
	});

	it("under-floor queue: ineligible pending work keeps no alarm", async () => {
		const stub = await freshStub();
		// The floor is stamped into `settings` by migrate — set it first.
		(env as Env2).STOW_MIN_DISPATCH_VALUE = "1000000";
		try {
			await migrate(stub);
			// downloads=1 → value far below the stamped floor → the row is
			// admitted but dispatch-ineligible until demand rises.
			const { status } = await submit(stub, [enqueue("idle-floor", [], 1)]);
			expect(status).toBe(200);
			// Submit's own schedule_alarm already resolved Delete.
			expect(await getAlarm(stub)).toBeNull();
			await expectQuiescent(stub, { pending: 1 });
		} finally {
			delete (env as Env2).STOW_MIN_DISPATCH_VALUE;
		}
	});

	it("paused dispatch: capacity zero claims nothing and stops waking", async () => {
		const stub = await freshStub();
		(env as Env2).STOW_MAX_CONCURRENT_JOBS = "0";
		try {
			await migrate(stub);
			const { status } = await submit(stub, [enqueue("idle-paused")]);
			expect(status).toBe(200);
			expect(await getAlarm(stub)).toBeNull();
			await expectQuiescent(stub, { pending: 1 });
		} finally {
			delete (env as Env2).STOW_MAX_CONCURRENT_JOBS;
		}
	});

	it("frozen dispatch: the freeze record eats the wake", async () => {
		const stub = await freshStub();
		await migrate(stub);

		// Freeze before the queue has work: the trusted lane refuses, the
		// untrusted lane still admits, and neither arms a wake.
		const res = await stub.fetch(`${DO}/dispatch-freeze`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ enabled: true, reason: "idle-proof" }),
		});
		expect(res.status).toBe(200);

		const { status } = await submit(stub, [enqueue("idle-frozen")]);
		expect(status).toBe(200);
		expect(await getAlarm(stub)).toBeNull();
		await expectQuiescent(stub, { pending: 1 });

		// The freeze also declines trusted submits with its reason.
		const refused = await submitTrusted(stub, [enqueue("idle-frozen-2")]);
		expect(refused.status).toBe(503);
	});
});
