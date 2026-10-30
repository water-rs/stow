import path from "node:path";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// The real workerd build — the bundle `skyzen build --provider cloudflare
// --manifest edge/Skyzen.mock.toml` emits — not a reimplementation. The
// generated wrangler config carries the mock vars (STOW_LOCAL_CI_URL,
// STOW_STALE_DISPATCH_MINUTES=10080, …) the production deploy inputs mirror.

// The dispatch stub stands in for the two loopback services the mock
// build points at: the local-CI server `STOW_LOCAL_CI_URL` names
// (127.0.0.1:28124 — the `/dispatch` event POST plus the GitHub-shaped
// run endpoints `LocalCiBuildRuns` serves) and the registry
// `GHCR_BASE_URL` names (127.0.0.1:28123 — the OCI manifest read the
// records check makes per successful task). It is ALSO the egress
// audit: it is the sole `outboundService` for every worker under test,
// so any fetch the scheduler attempts lands here, and anything outside
// a task run's lifecycle answers 500 — a poisoned call poisons the queue
// row the next assertion reads.
//
// A `POST /dispatch` records the `build-crate` task payload and binds a
// run id; `GET …/runs/{id}` answers that run's status; `GET
// …/runs/{id}/attempts/{n}/jobs` answers the one page whose `build
// <crate> <version> (<target>)`/`publish` jobs and `VERDICT_STEPS`
// steps classify the task as success; and `GET /v2/…/manifests/records-…`
// answers the manifest whose `artifactType` and task-id annotation the
// records check requires. No cosign material is involved on this read
// path — the check is manifest shape, not signature verification.
const DISPATCH_STUB = String.raw`
// The periodic workflows the edge's Cron Trigger dispatched (stow#1100),
// in arrival order — scheduled.test.ts reads and clears them through
// /__control/periodic.
const periodic = [];

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
	async fetch(request) {
		const url = new URL(request.url);
		const origin = url.origin;
		// STOW_LOCAL_CI_URL: the /dispatch event POST and the
		// GitHub-shaped run endpoints under /repos/{owner}/{repo}/actions.
		if (url.port === "28124") {
			if (url.pathname === "/__control/periodic") {
				if (request.method === "POST") {
					periodic.length = 0;
					return new Response(null, { status: 204 });
				}
				return Response.json(periodic);
			}
			if (request.method === "POST" && url.pathname === "/dispatch") {
				const body = await request.json();
				if (body.event_type === "watchdog" || body.event_type === "preheat-cron") {
					periodic.push(body.event_type);
					return Response.json({ ok: true });
				}
				if (body.event_type !== "build-crate" || !body.client_payload) {
					return new Response("unexpected dispatch event", { status: 500 });
				}
				const runId = nextRunId++;
				runs.set(runId, body.client_payload);
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
`;

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: {
				configPath: path.resolve(
					import.meta.dirname,
					"../../.skyzen/gen/wrangler.toml",
				),
			},
			miniflare: {
				outboundService: "dispatch-stub",
				workers: [
					{
						name: "dispatch-stub",
						modules: true,
						script: DISPATCH_STUB,
						compatibilityDate: "2025-02-01",
					},
				],
			},
		}),
	],
});