// stow#1088 — the OIDC RS256 check on the real workerd build.
//
// The host build has no signature verifier (the repository keeps no code
// that production never runs), so the signature path is proven here, where
// WebCrypto exists: the edge worker under test imports the JWK served by
// the dispatch stub's mock issuer (vitest.config.ts) and verifies tokens
// this file signs with its own WebCrypto keys. The route is
// `GET /api/v1/admin/status`, which takes the bearer check and then asks
// the (here uninitialised) scheduler: 401 is the bearer check refusing,
// any other answer means it admitted the token.

import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

const ISSUER = "https://token.actions.githubusercontent.com";
const WORKFLOW =
	"water-rs/stow/.github/workflows/preheat-admin.yml@refs/heads/main";
const CONTROL = "http://127.0.0.1:28123/__control/jwks";
const RS256 = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;

type Signer = { kid: string; pair: CryptoKeyPair; jwk: JsonWebKey };

let kids = 0;
async function newSigner(): Promise<Signer> {
	const pair = (await crypto.subtle.generateKey(
		{ ...RS256, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	return { kid: `kid-${kids++}`, pair, jwk };
}

async function publish(...signers: Signer[]) {
	const keys = signers.map(({ kid, jwk }) => ({
		kty: "RSA",
		kid,
		n: jwk.n,
		e: jwk.e,
	}));
	const res = await fetch(CONTROL, {
		method: "POST",
		body: JSON.stringify({ keys }),
	});
	expect(res.status).toBe(204);
}

async function jwksFetches(): Promise<number> {
	const res = await fetch(CONTROL);
	return ((await res.json()) as { fetches: number }).fetches;
}

function b64url(bytes: ArrayBuffer | Uint8Array | string): string {
	const data =
		typeof bytes === "string" ? new TextEncoder().encode(bytes) : new Uint8Array(bytes);
	return btoa(String.fromCharCode(...data))
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replaceAll("=", "");
}

function claims(overrides: Record<string, unknown> = {}) {
	const now = Math.floor(Date.now() / 1000);
	return {
		iss: ISSUER,
		aud: "https://stow.waterui.dev",
		exp: now + 600,
		nbf: now - 60,
		repository: "water-rs/stow",
		job_workflow_ref: WORKFLOW,
		workflow_ref: WORKFLOW,
		run_id: "12345",
		run_attempt: "1",
		ref: "refs/heads/main",
		actor: "octo-dispatcher",
		...overrides,
	};
}

async function mint(
	signer: Signer,
	payload: object = claims(),
	header: Record<string, unknown> = {},
): Promise<string> {
	const input = `${b64url(
		JSON.stringify({ alg: "RS256", typ: "JWT", kid: signer.kid, ...header }),
	)}.${b64url(JSON.stringify(payload))}`;
	const signature = await crypto.subtle.sign(
		RS256,
		signer.pair.privateKey,
		new TextEncoder().encode(input),
	);
	return `${input}.${b64url(signature)}`;
}

async function status(token: string): Promise<number> {
	const res = await exports.default.fetch(
		"https://stow.test/api/v1/admin/status",
		{ headers: { authorization: `Bearer ${token}` } },
	);
	await res.arrayBuffer();
	return res.status;
}

// The first request instantiates the 34 MiB wasm bundle cold, which runs
// past vitest's default 5 s.
describe("OIDC RS256 verification on WebCrypto (stow#1088)", { timeout: 60_000 }, () => {
	it("admits a validly signed token", async () => {
		const signer = await newSigner();
		await publish(signer);
		expect(await status(await mint(signer))).not.toBe(401);
	});

	it("serves a known kid from the isolate's key cache", async () => {
		const signer = await newSigner();
		await publish(signer);
		const token = await mint(signer);
		for (let i = 0; i < 3; i++) {
			expect(await status(token)).not.toBe(401);
		}
		expect(await jwksFetches()).toBe(1);
	});

	it("refuses a tampered payload", async () => {
		const signer = await newSigner();
		await publish(signer);
		const [header, , signature] = (await mint(signer)).split(".");
		const forged = b64url(JSON.stringify(claims({ actor: "someone-else" })));
		expect(await status(`${header}.${forged}.${signature}`)).toBe(401);
	});

	it("refuses a token signed by a key the issuer does not list", async () => {
		const listed = await newSigner();
		const forger = await newSigner();
		await publish(listed);
		// The forger signs under the listed kid, so the edge verifies with
		// the listed key and the signature cannot match.
		expect(await status(await mint({ ...forger, kid: listed.kid }))).toBe(401);
	});

	it("refetches once for an unknown kid and refuses it", async () => {
		const known = await newSigner();
		const stranger = await newSigner();
		await publish(known);
		expect(await status(await mint(known))).not.toBe(401);
		expect(await jwksFetches()).toBe(1);
		expect(await status(await mint(stranger))).toBe(401);
		expect(await jwksFetches()).toBe(2);
	});

	it("picks up a rotated key on the refetch an unknown kid triggers", async () => {
		const old = await newSigner();
		const rotated = await newSigner();
		await publish(old);
		expect(await status(await mint(old))).not.toBe(401);
		await publish(old, rotated);
		expect(await status(await mint(rotated))).not.toBe(401);
		expect(await jwksFetches()).toBe(1);
	});

	it("refuses a non-RS256 alg", async () => {
		const signer = await newSigner();
		await publish(signer);
		expect(await status(await mint(signer, claims(), { alg: "HS256" }))).toBe(401);
		expect(await status(await mint(signer, claims(), { alg: "none" }))).toBe(401);
	});

	it("refuses claims that do not pin this deployment even when signed", async () => {
		const signer = await newSigner();
		await publish(signer);
		expect(
			await status(await mint(signer, claims({ repository: "someone/else" }))),
		).toBe(401);
		expect(
			await status(await mint(signer, claims({ aud: "https://elsewhere.test" }))),
		).toBe(401);
		expect(
			await status(
				await mint(signer, claims({ exp: Math.floor(Date.now() / 1000) - 3600 })),
			),
		).toBe(401);
	});
});
