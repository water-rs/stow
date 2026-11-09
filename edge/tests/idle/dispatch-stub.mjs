import { externalResponse } from "./external-responses.mjs";

// The periodic workflows the edge's Cron Trigger dispatched (stow#1100),
// in arrival order — scheduled.test.ts reads and clears them through
// /__control/periodic.
const periodic = [];
let ciLimit = null;
let dispatchAttempts = 0;
let ciLatencyMs = 0;
const ciStatusRequests = [];
const resolves = [];
const externalCalls = [];
// The stems of the workflows STOW_PERIODIC_WORKFLOWS names in
// edge/Skyzen.mock.toml (stow#1121).
const PERIODIC_EVENTS = new Set([
	"watchdog",
	"preheat-cron",
	"index-publish-cron",
	"demand-feed",
	"build-failure-digest",
	"test",
	"release-gate",
	"preheat-projects",
	"preheat-missed",
]);

// The runs this isolate has dispatched, run id → BuildTaskPayload.
// One in-flight run per test makes collisions impossible, but the
// counter keeps the run ids distinct anyway.
const runs = new Map();
let nextRunId = 4242;

// The key set the mock OIDC issuer serves, and how often it was read.
let jwks = { keys: [] };
let jwksFetches = 0;

// types/src/runs.rs VERDICT_STEPS — the steps that run the crate or
// judge its outputs.
const VERDICT_STEPS = [
	"Run the untrusted build stage",
	"Report the built outputs' glibc floor",
	"Run the trusted publish stage",
];

const SETTLED = { status: "completed", conclusion: "success" };
const STEPS = VERDICT_STEPS.map((name) => ({ name, ...SETTLED }));

// The jobs page a successful build-crate run serves: the untrusted
// build job GitHub names "build <crate> <version> (<target>)" and the
// trusted "publish" job. Both completed-success with the timestamps the
// outcome read expects — build's started_at to publish's completed_at —
// and run_attempt naming the page's attempt.
function taskJobs(task, attempt, runUrl) {
	return [
		{
			id: 1000,
			name: "build " + task.crate_name + " " + task.version + " (" + task.target + ")",
			...SETTLED,
			started_at: "2026-01-01T00:00:00Z",
			completed_at: "2026-01-01T00:10:00Z",
			run_attempt: attempt,
			html_url: runUrl + "/job/1000",
			steps: STEPS,
		},
		{
			id: 1001,
			name: "publish",
			...SETTLED,
			started_at: "2026-01-01T00:10:00Z",
			completed_at: "2026-01-01T00:12:00Z",
			run_attempt: attempt,
			html_url: runUrl + "/job/1001",
			steps: STEPS,
		},
	];
}

export default {
	async fetch(request, env) {
		const external = await externalResponse(request, env);
		if (external) {
			externalCalls.push(request.url);
			return external;
		}
		const url = new URL(request.url);
		const origin = url.origin;
		// STOW_LOCAL_CI_URL: the /dispatch event POST and the
		// GitHub-shaped run endpoints under /repos/{owner}/{repo}/actions.
		if (url.port === "28124") {
			if (url.pathname === "/__control/ci-latency") {
				if (request.method === "POST") {
					ciLatencyMs = (await request.json()).milliseconds;
					return new Response(null, { status: 204 });
				}
				return Response.json({ statusRequests: ciStatusRequests });
			}
			if (url.pathname === "/__control/ci-limit") {
				if (request.method === "POST") {
					ciLimit = (await request.json()).mode;
					dispatchAttempts = 0;
					return new Response(null, { status: 204 });
				}
				return Response.json({ attempts: dispatchAttempts });
			}
			if (url.pathname === "/__control/human-reset" && request.method === "POST") {
				resolves.length = 0;
				externalCalls.length = 0;
				return new Response(null, { status: 204 });
			}
			if (url.pathname === "/__control/resolve") return Response.json(resolves);
			if (url.pathname === "/__control/external") return Response.json(externalCalls);
			if (url.pathname === "/__control/periodic") {
				if (request.method === "POST") {
					periodic.length = 0;
					ciLimit = null;
					ciLatencyMs = 0;
					ciStatusRequests.length = 0;
					dispatchAttempts = 0;
					return new Response(null, { status: 204 });
				}
				return Response.json(periodic);
			}
			if (request.method === "GET" && /^\/repos\/[^/]+\/[^/]+\/actions\/workflows\/build-crate\.yml\/runs$/.test(url.pathname)) {
				const status = url.searchParams.get("status");
				if (status !== "queued" && status !== "in_progress") {
					return new Response("unexpected CI status query", { status: 500 });
				}
				ciStatusRequests.push(status);
				if (ciLatencyMs > 0) {
					await new Promise((resolve) => setTimeout(resolve, ciLatencyMs));
				}
				// This fixture completes every build run immediately; its
				// queued and running lists are therefore both empty.
				return Response.json({ workflow_runs: [] });
			}
			if (request.method === "POST" && url.pathname === "/dispatch") {
				dispatchAttempts++;
				if (ciLatencyMs > 0) {
					await new Promise((resolve) => setTimeout(resolve, ciLatencyMs));
				}
				if (ciLimit) {
					const headers = ciLimit === "primary"
						? { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(Math.floor(Date.now() / 1000) + 60) }
						: { "retry-after": "60" };
					return new Response("rate limited", { status: 403, headers });
				}
				const body = await request.json();
				if (body.event_type === "preheat") return new Response(null, { status: 204 });
				if (body.event_type === "resolve-request" && body.client_payload) {
					resolves.push(body.client_payload);
					return new Response(null, { status: 204 });
				}
				if (PERIODIC_EVENTS.has(body.event_type)) {
					periodic.push(body.event_type);
					return Response.json({ ok: true });
				}
				if (body.event_type !== "build-crate" || !body.client_payload) {
					return new Response("unexpected dispatch event", { status: 500 });
				}
				const runId = nextRunId++;
				runs.set(runId, body.client_payload);
				const name = body.client_payload.crate_name;
				if (name === "timeout-headers") {
					await new Promise((resolve) => setTimeout(resolve, 8000));
				}
				if (name === "timeout-body") {
					let timer;
					const stream = new ReadableStream({
						start(controller) {
							controller.enqueue(new TextEncoder().encode('{"workflow_run_id":'));
							timer = setTimeout(() => {
								controller.enqueue(new TextEncoder().encode(JSON.stringify(runId) + '}'));
								controller.close();
							}, 8000);
						},
						cancel() {
							clearTimeout(timer);
						},
					});
					return new Response(stream, { headers: { "content-type": "application/json" } });
				}
				return Response.json({
					workflow_run_id: runId,
					run_url: origin + "/runs/" + runId,
					html_url: origin + "/runs/" + runId,
				});
			}
			let match = url.pathname.match(
				/^\/repos\/[^/]+\/[^/]+\/actions\/runs\/([0-9]+)$/,
			);
			if (match && runs.has(Number(match[1]))) {
				return Response.json({
					status: "completed",
					conclusion: "success",
					run_attempt: 1,
					html_url: origin + "/runs/" + match[1],
				});
			}
			match = url.pathname.match(
				/^\/repos\/[^/]+\/[^/]+\/actions\/runs\/([0-9]+)\/attempts\/([0-9]+)\/jobs$/,
			);
			if (match && runs.has(Number(match[1]))) {
				const task = runs.get(Number(match[1]));
				return Response.json({
					jobs: taskJobs(task, Number(match[2]), origin + "/runs/" + match[1]),
				});
			}
		}
		// GHCR_BASE_URL: the OCI manifest read the records check makes —
		// artifactType and the task-id annotation must both match or the
		// task resolves as records-absent. The tag
		// records-<rustc>-<blake3(task_id)>-<run>-<attempt> names the run
		// in its last-but-one leg, and that run's task is the only task
		// the tag may answer for.
		if (url.port === "28123") {
			// The OIDC issuer's key set the bearer check fetches
			// (STOW_GITHUB_API_URL), set and counted by oidc.test.ts through
			// the control routes: the JWKS is the test's, and the fetch count
			// shows what the edge's per-isolate key cache absorbed.
			if (url.pathname === "/__control/jwks") {
				if (request.method === "POST") {
					jwks = await request.json();
					jwksFetches = 0;
					return new Response(null, { status: 204 });
				}
				return Response.json({ fetches: jwksFetches });
			}
			if (url.pathname === "/.well-known/jwks") {
				jwksFetches++;
				return Response.json(jwks);
			}
			const match = url.pathname.match(
				/^\/v2\/[^/]+\/[^/]+\/manifests\/(records-.+)$/,
			);
			if (match) {
				const runId = match[1].split("-").slice(-2)[0];
				const task = runs.get(Number(runId));
				if (task) {
					// ghcr::records_artifact_exists reads only
					// artifactType and the task-id annotation.
					return Response.json({
						schemaVersion: 2,
						mediaType: "application/vnd.oci.image.manifest.v1+json",
						artifactType: "application/vnd.stow.records.v1+json",
						annotations: { "dev.stow.records.task-id": task.task_id },
					});
				}
			}
		}
		return new Response("unmocked outbound fetch: " + url, { status: 500 });
	},
};
