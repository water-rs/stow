import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// The real workerd build — the bundle `skyzen build --provider cloudflare
// --manifest edge/Skyzen.mock.toml` emits — not a reimplementation. The
// generated wrangler config carries the mock vars (STOW_LOCAL_CI_URL,
// STOW_STALE_DISPATCH_MINUTES=10, …) the production deploy inputs mirror.
const migrations = await readD1Migrations(
	path.resolve(import.meta.dirname, "../../migrations"),
);

// The dispatch stub stands in for the local-CI server the build
// points STOW_LOCAL_CI_URL at. It is ALSO the egress audit: it is the
// sole `outboundService` for every worker under test, so any fetch the
// scheduler attempts — dispatch or otherwise — lands here. Only
// `<STOW_LOCAL_CI_URL>/dispatch` answers with a real run record;
// anything else returns 500 and therefore cannot pass silently: a
// poisoned dispatch poisons the queue row the next assertion reads.
const DISPATCH_STUB = `
export default {
	async fetch(request) {
		const url = new URL(request.url);
		if (url.hostname === "127.0.0.1" && url.pathname === "/dispatch") {
			return Response.json({
				workflow_run_id: 4242,
				run_url: url.origin + "/tasks/4242",
				html_url: url.origin + "/tasks/4242",
			});
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
				bindings: { TEST_MIGRATIONS: migrations },
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
