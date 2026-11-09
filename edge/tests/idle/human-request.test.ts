import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

const CONTROL = "http://127.0.0.1:28124/__control";

async function control(path: string) {
	const response = await fetch(`${CONTROL}/${path}`);
	expect(response.status).toBe(200);
	return response.json() as Promise<unknown[]>;
}

async function request(token: string) {
	return exports.default.fetch("https://stow.test/api/v1/requests", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			crate_name: "serde",
			version: "1.0.228",
			features_json: "[]",
			turnstile_token: token,
		}),
	});
}

describe("human requests on the native outbound boundary", { timeout: 60_000 }, () => {
	beforeEach(async () => {
		const response = await fetch(`${CONTROL}/human-reset`, { method: "POST" });
		expect(response.status).toBe(204);
	});

	it("resolves real upstream data and dispatches the admitted identity", async () => {
		const stub = env.SCHEDULER.get(env.SCHEDULER.idFromName("scheduler"));
		const reset = await stub.fetch("https://scheduler.invalid/reset", {
			method: "POST",
			headers: { "x-stow-actor": "human-request-test" },
		});
		expect(reset.status).toBe(200);
		await reset.arrayBuffer();
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
