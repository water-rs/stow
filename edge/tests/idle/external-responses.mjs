// Native outbound service responses shared by idle and CPU tests.
// Unknown URLs remain the caller's responsibility and must fail closed.
export async function externalResponse(request, env) {
	const url = new URL(request.url);
	if (url.href === "https://challenges.cloudflare.com/turnstile/v0/siteverify" && request.method === "POST") {
		const form = await request.formData();
		if (form.get("secret") !== "1x0000000000000000000000000000000AA") {
			throw new Error("unexpected Turnstile secret in mock request");
		}
		return Response.json(form.get("response") === "reject"
			? { success: false, "error-codes": ["invalid-input-response"] }
			: { success: true, hostname: "example.com" });
	}
	if (url.href === "https://index.crates.io/se/rd/serde" && request.method === "GET") {
		return new Response(env.SERDE_INDEX, { headers: { "content-type": "text/plain" } });
	}
	if (url.href === "https://static.rust-lang.org/dist/channel-rust-stable.toml" && request.method === "GET") {
		return new Response(env.STABLE_MANIFEST, { headers: { "content-type": "text/plain" } });
	}
}
