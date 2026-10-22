import { readFileSync } from "node:fs";
import path from "node:path";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { unstable_splitSqlQuery } from "wrangler";

// The real workerd build — the bundle `skyzen build --provider cloudflare
// --manifest edge/Skyzen.mock.toml` emits — not a reimplementation. The
// generated wrangler config carries the mock vars (STOW_LOCAL_CI_URL,
// STOW_STALE_DISPATCH_MINUTES=10080, …) the production deploy inputs mirror.
// The D1 catalog has one schema — the same file an operator applies.
const d1Schema = readFileSync(
	path.resolve(import.meta.dirname, "../../schema.sql"),
	"utf8",
);

// The dispatch stub stands in for the two loopback services the mock
// build points at: the local-CI server `STOW_LOCAL_CI_URL` names
// (127.0.0.1:28124 — the `/dispatch` event POST plus the GitHub-shaped
// run endpoints `LocalCiBuildRuns` serves) and the registry
// `GHCR_BASE_URL` names (127.0.0.1:28123 — the OCI manifest read the
// batch resolution makes per successful leg). It is ALSO the egress
// audit: it is the sole `outboundService` for every worker under test,
// so any fetch the scheduler attempts lands here, and anything outside
// a batch's lifecycle answers 500 — a poisoned call poisons the queue
// row the next assertion reads.
//
// A `POST /dispatch` records the `build-batch` payload and binds a run
// id; `GET …/runs/{id}` answers that run's status; `GET
// …/runs/{id}/attempts/{n}/jobs` answers the one page whose `build #i`/
// `publish #i` job names and `VERDICT_STEPS` steps classify every leg
// as success; and `GET /v2/…/manifests/records-…` answers the manifest
// whose `artifactType` and task-id annotation the records check
// requires. No cosign material is involved on this read path — the
// check is manifest shape, not signature verification.
const DISPATCH_STUB = `
// The runs this isolate has dispatched, run id → BuildBatchPayload.
// One in-flight batch per test makes collisions impossible, but the
// counter keeps the run ids distinct anyway.
const runs = new Map();
let nextRunId = 4242;

// types/src/runs.rs VERDICT_STEPS — the steps that run the crate or
// judge its outputs.
const VERDICT_STEPS = [
	"Run the untrusted build stage",
	"Report the built outputs' glibc floor",
	"Run the trusted publish stage",
];

const SETTLED = { status: "completed", conclusion: "success" };
const STEPS = VERDICT_STEPS.map((name) => ({ name, ...SETTLED }));

// The jobs page a successful build-batch run serves: per leg, the
// untrusted build job and the trusted publish job GitHub names
// "leg <i> / build #<i> <crate> <version> (<target>) <hash>" and
// "leg <i> / publish #<i> <hash>" (LegJobName::parse drops the
// caller-job prefix at the last " / "). Both completed-success with
// the timestamps LegOutcome::Succeeded reads — build's started_at to
// publish's completed_at — and run_attempt naming the page's attempt.
function legJobs(batch, attempt, runUrl) {
	const jobs = [];
	for (const leg of batch.tasks) {
		const label = leg.crate_name + " " + leg.version + " (" + leg.target + ")";
		jobs.push({
			id: 1000 + leg.i * 2,
			name: "leg " + leg.i + " / build #" + leg.i + " " + label + " " + leg.h,
			...SETTLED,
			started_at: "2026-01-01T00:00:00Z",
			completed_at: "2026-01-01T00:10:00Z",
			run_attempt: attempt,
			html_url: runUrl + "/job/" + (leg.i * 2),
			steps: STEPS,
		});
		jobs.push({
			id: 1001 + leg.i * 2,
			name: "leg " + leg.i + " / publish #" + leg.i + " " + leg.h,
			...SETTLED,
			started_at: "2026-01-01T00:10:00Z",
			completed_at: "2026-01-01T00:12:00Z",
			run_attempt: attempt,
			html_url: runUrl + "/job/" + (leg.i * 2 + 1),
			steps: STEPS,
		});
	}
	return jobs;
}

// The leg a records tag names: records-<rustc>-<blake3(task_id)>-<run>-<attempt>,
// and the batch's own task hash is that digest's first 16 hex.
function tagLeg(batch, tag) {
	const match = tag.match(/^records-[^-]+-([0-9a-f]{64})-([0-9]+)-([0-9]+)$/);
	if (!match) return null;
	return batch.tasks.find((leg) => match[1].startsWith(leg.h)) ?? null;
}

export default {
	async fetch(request) {
		const url = new URL(request.url);
		const origin = url.origin;
		// STOW_LOCAL_CI_URL: the /dispatch event POST and the
		// GitHub-shaped run endpoints under /repos/{owner}/{repo}/actions.
		if (url.port === "28124") {
			if (request.method === "POST" && url.pathname === "/dispatch") {
				const body = await request.json();
				if (body.event_type !== "build-batch" || !body.client_payload) {
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
				/^\\/repos\\/[^/]+\\/[^/]+\\/actions\\/runs\\/([0-9]+)$/,
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
				/^\\/repos\\/[^/]+\\/[^/]+\\/actions\\/runs\\/([0-9]+)\\/attempts\\/([0-9]+)\\/jobs$/,
			);
			if (match && runs.has(Number(match[1]))) {
				const batch = runs.get(Number(match[1]));
				return Response.json({
					jobs: legJobs(batch, Number(match[2]), origin + "/runs/" + match[1]),
				});
			}
		}
		// GHCR_BASE_URL: the OCI manifest read the records check makes —
		// artifactType and the task-id annotation must both match or the
		// leg resolves as records-absent.
		if (url.port === "28123") {
			const match = url.pathname.match(
				/^\\/v2\\/[^/]+\\/[^/]+\\/manifests\\/(records-.+)$/,
			);
			if (match) {
				// The tag's trailing pair is <run_id>-<attempt>; the run
				// scopes which batch's legs the tag may name.
				const runId = match[1].split("-").slice(-2)[0];
				const batch = runs.get(Number(runId));
				const leg = batch && tagLeg(batch, match[1]);
				if (leg) {
					// ghcr::records_artifact_exists reads only
					// artifactType and the task-id annotation.
					return Response.json({
						schemaVersion: 2,
						mediaType: "application/vnd.oci.image.manifest.v1+json",
						artifactType: "application/vnd.stow.records.v1+json",
						annotations: { "dev.stow.records.task-id": leg.task_id },
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
				// The operator applies the schema with `wrangler d1 execute
				// --file`, which splits the file statement-wise and batches
				// prepared statements — never `exec`, which treats each line
				// as a statement and dies on this file's comment lines. The
				// same splitter produces the statements the test batches.
				bindings: {
					TEST_D1_STATEMENTS: JSON.stringify(
						unstable_splitSqlQuery(d1Schema),
					),
				},
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