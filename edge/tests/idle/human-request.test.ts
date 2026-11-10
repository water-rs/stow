import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { claims, mint, newSigner, publish } from "./oidc-fixture";

const CONTROL = "http://127.0.0.1:28124/__control";

async function control(path: string) {
	const response = await fetch(`${CONTROL}/${path}`);
	expect(response.status).toBe(200);
	return response.json() as Promise<unknown[]>;
}

async function request(token: string, version = "1.0.228") {
	return exports.default.fetch("https://stow.test/api/v1/requests", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			crate_name: "serde",
			version,
			features_json: "[]",
			turnstile_token: token,
		}),
	});
}

async function resolveToken(workflow = "resolve-request.yml") {
	const signer = await newSigner();
	await publish(signer);
	const reference = `water-rs/stow/.github/workflows/${workflow}@refs/heads/main`;
	return mint(signer, claims({ workflow_ref: reference, job_workflow_ref: reference }));
}

async function report(requestId: string, token: string, outcome: object) {
	return exports.default.fetch(`https://stow.test/api/v1/scheduler/requests/${requestId}/outcome`, {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: JSON.stringify({ attempt: 1, outcome }),
	});
}

async function status(requestId: string) {
	const response = await exports.default.fetch(`https://stow.test/api/v1/requests/${requestId}`);
	expect(response.status).toBe(200);
	return response.json() as Promise<{ status: string; error: string; github_run_id: string }>;
}

async function delivery(requestId: string, action: string, conclusion: string | null) {
	const body = JSON.stringify({
		action,
		repository: { full_name: "water-rs/stow" },
		workflow_run: {
			display_title: `resolve-a1-${requestId}`, event: "workflow_dispatch",
			head_branch: "main", path: ".github/workflows/resolve-request.yml",
			conclusion, id: 12345, run_attempt: 1,
			html_url: "https://github.com/water-rs/stow/actions/runs/12345",
			head_repository: { full_name: "water-rs/stow" },
			triggering_actor: { login: "octo-dispatcher" },
		},
	});
	const key = await crypto.subtle.importKey("raw",
		new TextEncoder().encode("mock-github-webhook-secret"),
		{ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)));
	const hex = Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
	const response = await exports.default.fetch("https://stow.test/api/v1/github/workflow-run", {
		method: "POST", body,
		headers: { "content-type": "application/json", "x-github-event": "workflow_run", "x-hub-signature-256": `sha256=${hex}` },
	});
	expect(response.status, await response.text()).toBe(200);
}

describe("human requests on the native outbound boundary", { timeout: 60_000 }, () => {
	beforeEach(async () => {
		const response = await fetch(`${CONTROL}/human-reset`, { method: "POST" });
		expect(response.status).toBe(204);
		const stub = env.SCHEDULER.get(env.SCHEDULER.idFromName("scheduler"));
		const reset = await stub.fetch("https://scheduler.invalid/reset", {
			method: "POST",
			headers: { "x-stow-actor": "human-request-test" },
		});
		expect(reset.status).toBe(200);
		await reset.arrayBuffer();
	});

	it("resolves real upstream data and dispatches the admitted identity", async () => {
		const response = await request("pass");
		const status = await response.json() as { request_id: string; status: string; rustc_version: string };
		expect(response.status, JSON.stringify(status)).toBe(200);
		expect(status.status).toBe("accepted");
		expect(status.rustc_version).toBe("1.99.1");
		expect(await control("resolve")).toEqual([expect.objectContaining({
			request_id: status.request_id,
			crate_name: "serde",
			version: "1.0.228",
			features_json: "[]",
			rustc_version: "1.99.1",
			attempt: 1,
		})]);
		expect(await control("external")).toEqual(expect.arrayContaining([
			"https://challenges.cloudflare.com/turnstile/v0/siteverify",
			"https://index.crates.io/se/rd/serde",
			"https://static.rust-lang.org/dist/channel-rust-stable.toml",
		]));
	});

	it("authenticates a failed resolve report and persists its outcome", async () => {
		const response = await request("pass");
		const { request_id: id } = await response.json() as { request_id: string };
		const outcome = { kind: "failed", error: "resolver fixture: target configuration cannot resolve" };
		const refused = await report(id, await resolveToken("operations.yml"), outcome);
		expect(refused.status).toBe(401);
		await refused.arrayBuffer();
		expect((await status(id)).status).toBe("accepted");
		await delivery(id, "in_progress", null);
		expect(await status(id)).toMatchObject({ status: "resolving", github_run_id: "12345" });
		const settled = await report(id, await resolveToken(), outcome);
		expect(settled.status, await settled.text()).toBe(200);
		await delivery(id, "completed", "failure");
		expect(await status(id)).toMatchObject({ status: "failed", error: outcome.error });
	});

	it("enqueues a nonempty resolved tree and keeps it after completion", async () => {
		const response = await request("pass", "1.0.219");
		const { request_id: id } = await response.json() as { request_id: string };
		await delivery(id, "requested", null);
		expect((await status(id)).status).toBe("accepted");
		await delivery(id, "in_progress", null);
		const featuresHash = id.slice("req-serde-1.0.219-".length, -"-1.99.1".length);
		// The same synthetic dependency digest convention as idle.test.ts.
		const digest = "1".padStart(64, "0");
		const targets = ["aarch64-apple-darwin", "aarch64-apple-ios", "aarch64-apple-ios-sim",
			"aarch64-linux-android", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
			"x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc", "wasm32-unknown-unknown"];
		const nodes = targets.map((target) => ({
			task_id: `serde-1.0.219-${featuresHash}-${target.replaceAll("-", "_")}-1.99.1-d${digest}`,
			crate_name: "serde", version: "1.0.219", features_json: "[]", target,
			rustc_version: "1.99.1", dependency_identity: digest, explicit_spelling: "keys-as-native", deps: [],
		}));
		const settled = await report(id, await resolveToken(), {
			kind: "resolved",
			trees: [{ source: { kind: "human_request" }, roots: nodes.map((_, i) => i), nodes }],
			roots: nodes.map(({ target, task_id }) => ({ target, task_id, cached: false })),
		});
		const result = await settled.json() as { status: string; targets: unknown[] };
		expect(settled.status, JSON.stringify(result)).toBe(200);
		expect(result.status).toBe("enqueued");
		expect(result.targets).toHaveLength(targets.length);
		await delivery(id, "completed", "success");
		expect((await status(id)).status).toBe("enqueued");
	});

	it("rejects Turnstile before resolving or dispatching", async () => {
		const response = await request("reject");
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({
			error: "turnstile rejected",
			"error-codes": ["invalid-input-response"],
		});
		expect(await control("resolve")).toEqual([]);
		expect(await control("external")).toEqual([
			"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		]);
	});
});
