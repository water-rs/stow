import { createHash } from "node:crypto";
import path from "node:path";

export function outboundModules(entry) {
	return [entry, "external-responses.mjs"].map((file) => ({
		type: "ESModule",
		path: path.resolve(import.meta.dirname, file),
	}));
}

// Full upstream inputs, fetched before the profiled Worker starts.
const sources = {
	SERDE_INDEX: {
		url: "https://raw.githubusercontent.com/rust-lang/crates.io-index/e01f438da0564e13f027e5d06b5e2688e05e13cf/se/rd/serde",
		sha256: "9eb6e78eab279f168b5787e4eb801765e1d5a2b40c50789e12166a616d73bbc5",
	},
	STABLE_MANIFEST: {
		url: "https://static.rust-lang.org/dist/2026-10-15/channel-rust-stable.toml",
		sha256: "fb152be80975c194aa5fc684b2aec3a6e14e2b855efe2faa4e5f8ae6e590f463",
	},
};

export async function externalBindings() {
	return Object.fromEntries(await Promise.all(Object.entries(sources).map(async ([name, source]) => {
		const response = await fetch(source.url, { signal: AbortSignal.timeout(20_000) });
		if (!response.ok) throw new Error(`${source.url}: HTTP ${response.status}`);
		const bytes = new Uint8Array(await response.arrayBuffer());
		const digest = createHash("sha256").update(bytes).digest("hex");
		if (digest !== source.sha256) throw new Error(`${source.url}: SHA-256 mismatch: ${digest}`);
		return [name, new TextDecoder("utf-8", { fatal: true }).decode(bytes)];
	})));
}
