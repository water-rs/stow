// Test issuer shared by native authentication and lifecycle regressions.

import { expect } from "vitest";

const ISSUER = "https://token.actions.githubusercontent.com";
// Injected by vitest.config.ts: `v` and the workspace version.
declare const RELEASE_TAG: string;
/** The ref the edge under test admits and dispatches on. */
export const RELEASE_REF = `refs/tags/${RELEASE_TAG}`;
const WORKFLOW = `water-rs/stow/.github/workflows/preheat-admin.yml@${RELEASE_REF}`;
const CONTROL = "http://127.0.0.1:28123/__control/jwks";
const RS256 = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;

type Signer = { kid: string; pair: CryptoKeyPair; jwk: JsonWebKey };

let kids = 0;
export async function newSigner(): Promise<Signer> {
	const pair = (await crypto.subtle.generateKey(
		{ ...RS256, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	return { kid: `kid-${kids++}`, pair, jwk };
}

export async function publish(...signers: Signer[]) {
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

export async function jwksFetches(): Promise<number> {
	const res = await fetch(CONTROL);
	return ((await res.json()) as { fetches: number }).fetches;
}

export function b64url(bytes: ArrayBuffer | Uint8Array | string): string {
	const data =
		typeof bytes === "string" ? new TextEncoder().encode(bytes) : new Uint8Array(bytes);
	return btoa(String.fromCharCode(...data))
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replaceAll("=", "");
}

export function claims(overrides: Record<string, unknown> = {}) {
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
		ref: RELEASE_REF,
		actor: "octo-dispatcher",
		...overrides,
	};
}

export async function mint(
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

