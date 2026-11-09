import { exports } from "cloudflare:workers";

export async function workflowRunDelivery(event: object) {
	const body = JSON.stringify(event);
	const key = await crypto.subtle.importKey("raw",
		new TextEncoder().encode("mock-github-webhook-secret"),
		{ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)));
	const hex = Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
	return exports.default.fetch("https://stow.test/api/v1/github/workflow-run", {
		method: "POST", body,
		headers: { "content-type": "application/json", "x-github-event": "workflow_run", "x-hub-signature-256": `sha256=${hex}` },
	});
}
