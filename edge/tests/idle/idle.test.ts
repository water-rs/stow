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
// The scheduler is initialized only through its operator `/reset`
// route — the same route `stow-admin scheduler reset --yes` invokes.
// No public probing endpoint and no production debug
// code is added: inspection goes through `runInDurableObject` on the
// real instance, and every outbound fetch routes through the
// `dispatch-stub` outbound service (see vitest.config.ts), which
// answers exactly what a task run's lifecycle needs — the `/dispatch`
// event POST, the run status and attempt-jobs reads, and the records
// manifest's GHCR GET — and 500s the rest: an egress this suite does
// not expect poisons the row under test.
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
	env,
	runDurableObjectAlarm,
	runInDurableObject,
} from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

const TARGET = "x86_64-unknown-linux-gnu";
const RUSTC = "1.98.1";
const DO = "https://scheduler.invalid";

type Env2 = typeof env & Record<string, string>;

// The submission wire (`SubmissionTree`): every node once, `deps` and
// `roots` as indexes into `nodes`. The scheduler merges by task id,
// re-derives it from the node's columns and refuses any other id, so a
// name maps to a stable 64-hex digest and the canonical task id over it.
const ids = new Map<string, string>();
function hexId(name: string) {
	if (!ids.has(name)) {
		ids.set(name, (ids.size + 1).toString(16).padStart(64, "0"));
	}
	return ids.get(name)!;
}

// BLAKE3 of the nodes' `features_json`, the id's feature segment.
const FEATURES_HASH =
	"ddd99a14d9fad9015908827b4edb6623350306075bbd2c2e5e600164d88b9618";

// The canonical task id (`stow_types::task_graph::canonical_task_id`).
function taskId(name: string) {
	const segment = (value: string) => value.replaceAll("-", "_");
	return `${name}-1.0.0-${FEATURES_HASH}-${segment(TARGET)}-${segment(RUSTC)}-d${hexId(name)}`;
}

function node(name: string, deps: number[], downloads: number) {
	return {
		task_id: taskId(name),
		crate_name: name,
		version: "1.0.0",
		features_json: '["default"]',
		target: TARGET,
		rustc_version: RUSTC,
		host_side: false,
		explicit_spelling: "keys-as-native",
		preserve_lockfile: false,
		dependency_identity: hexId(name),
		deps,
		downloads,
	};
}

// One cache-miss tree rooted at `name`, whose `deps` are bare copies of
// nodes the scheduler already holds.
function enqueue(name: string, deps: { crate_name: string }[] = [], downloads = 100) {
	return {
		source: { kind: "cache_miss" },
		roots: [deps.length],
		nodes: [
			...deps.map((dep) => node(dep.crate_name, [], 0)),
			node(
				name,
				deps.map((_, i) => i),
				downloads,
			),
		],
	};
}

function depOn(task: { crate_name: string }) {
	return task;
}

async function freshStub() {
	const id = env.SCHEDULER.newUniqueId();
	return env.SCHEDULER.get(id);
}

async function reset(stub: DurableObjectStub) {
	// Operator route only — the one place DDL may issue.
	const res = await stub.fetch(`${DO}/reset`, { method: "POST" });
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
		github_run_id: string | null;
		dispatch_attempts: number;
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

// Tasks by status, read through the scheduler's own listing: the graph
// lives in memory, so the route is the only view of it.
async function statusCounts(stub: DurableObjectStub) {
	const counts: Record<string, number> = {};
	for (const task of await tasks(stub)) {
		counts[task.status] = (counts[task.status] ?? 0) + 1;
	}
	return counts;
}

beforeAll(async () => {
	// `wrangler d1 execute --file` — the operator path — batches prepared
	// statements; `D1Database.exec` splits on newlines instead, so it
	// cannot load a file whose statements span lines and carry comments.
	const statements = JSON.parse(
		(env as Env2).TEST_D1_STATEMENTS,
	) as string[];
	await env.STOW_DB.batch(
		statements.map((sql) => env.STOW_DB.prepare(sql)),
	);
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

// The claimed task's bound run id once the dispatch response has
// landed it — the run the webhook's `completed` delivery then reports.
// The id lands ahead of the dispatch POST, so seeing `dispatched` is
// not yet proof the run is bound.
async function waitForRun(stub: DurableObjectStub, taskId: string) {
	for (let i = 0; i < 80; i++) {
		const runId = (await tasks(stub)).find((r) => r.task_id === taskId)
			?.github_run_id;
		if (runId != null) {
			return runId;
		}
		await new Promise((r) => setTimeout(r, 25));
	}
	throw new Error("no task bound a run for the claimed task");
}

// The full idle contract for a queue that has nothing to do. Two
// layers, in order:
//
//   1. Natural state — whatever alarm the real event (reset, submit,
//      run-complete, freeze) left armed. If one is armed, it must run
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
		const report = await reset(stub);
		expect(report).toBeTruthy();
		await expectQuiescent(stub, {});
	});

	it("completed work: a drained queue also stops waking", async () => {
		const stub = await freshStub();
		await reset(stub);
		const { status, body } = await submit(stub, [enqueue("idle-done")]);
		expect(status).toBe(200);
		expect(body.inserted).toBe(1);

		// Submit armed a real alarm; it fired on workerd's schedule,
		// claimed the task and dispatched its own run against the stub —
		// the only egress this suite permits.
		const rows = await waitForStatus(stub, "dispatched");
		const task = rows.find((r) => r.status === "dispatched")!;

		// The same route the workflow_run webhook drives: the report
		// names the task and its bound run, and lands the outcome on
		// its row for the alarm's resolution pass.
		const runId = await waitForRun(stub, task.task_id);
		const res = await stub.fetch(`${DO}/tasks/complete-run`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				task_id: task.task_id,
				success: true,
				github_run_id: runId,
			}),
		});
		expect(res.status).toBe(200);

		// The completion armed the pass at `resolve_after = now`; the
		// live alarm then read the run's jobs page and the task's
		// records manifest off the stub before completing the row.
		await waitForStatus(stub, "completed");
		const after = await statusCounts(stub);
		expect(after).toEqual({ completed: 1 });

		await expectQuiescent(stub, after);
	});

	it("positive control: an in-flight task lease keeps the alarm armed", async () => {
		const stub = await freshStub();
		await reset(stub);
		const { status } = await submit(stub, [enqueue("idle-inflight")]);
		expect(status).toBe(200);

		await waitForStatus(stub, "dispatched");
		const counts = await statusCounts(stub);
		expect(counts.dispatched ?? counts.running).toBe(1);

		// The lease is a per-task fact: the claiming pass wakes at the
		// in-flight row's `claimed_at + STOW_STALE_DISPATCH_MINUTES`
		// (`Graph::next_wake` minimizes it over
		// `dispatched`/`running`) — so the armed wake is exactly that
		// stored instant. Poll until the claiming pass has re-armed: a
		// mid-pass read would find the alarm still consumed.
		const staleMs =
			Number((env as Env2).STOW_STALE_DISPATCH_MINUTES) * 60_000;
		expect(staleMs).toBeGreaterThan(0);
		let armed: number | null = null;
		for (let i = 0; i < 80; i++) {
			const admin = (await (await stub.fetch(`${DO}/admin/status`)).json()) as {
				in_flight: { claimed_at: string }[];
			};
			const claimedMs =
				admin.in_flight.length === 0
					? null
					: Date.parse(admin.in_flight[0].claimed_at);
			const alarm = await getAlarm(stub);
			const leaseMs = claimedMs === null ? null : claimedMs + staleMs;
			// `claimed_at` is second-granular; the alarm holds the exact claim.
			if (
				leaseMs !== null &&
				alarm !== null &&
				Math.abs(alarm - leaseMs) < 1_000
			) {
				armed = alarm;
				break;
			}
			await new Promise((r) => setTimeout(r, 25));
		}
		expect(armed).not.toBeNull();
		// The stored lease is the claim plus the configured stale window,
		// checked against the binding itself rather than the row it
		// reads — a wrong lease formula cannot pass by agreeing with
		// itself. The tolerance covers claim-to-assert time.
		expect(Math.abs((armed as number) - (Date.now() + staleMs))).toBeLessThan(60_000);

		// A fired pass finds the task inside its lease — nothing
		// claimed, nothing resolved — and re-arms the same instant: a
		// disconnected or no-op instance cannot pass this check.
		expect(await runDurableObjectAlarm(stub)).toBe(true);
		expect(await getAlarm(stub)).toBe(armed);
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
			await reset(stub);
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
		// The floor is stamped into `settings` by reset — set it first.
		(env as Env2).STOW_MIN_DISPATCH_VALUE = "1000000";
		try {
			await reset(stub);
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
			await reset(stub);
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
		await reset(stub);

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
