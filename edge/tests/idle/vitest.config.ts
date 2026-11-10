import path from "node:path";
import { externalBindings, outboundModules } from "./external-data.mjs";
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

export default defineConfig(async () => ({
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
						modules: outboundModules("dispatch-stub.mjs"),
						modulesRoot: import.meta.dirname,
						bindings: await externalBindings(),
						compatibilityDate: "2025-02-01",
					},
				],
			},
		}),
	],
}));
