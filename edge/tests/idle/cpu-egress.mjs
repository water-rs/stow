import { externalResponse } from "./external-responses.mjs";

export default {
	async fetch(request, env) {
		const external = await externalResponse(request, env);
		if (external) return external;
		const origin = new URL(request.url).origin;
		if (JSON.parse(env.LOOPBACK_ORIGINS).includes(origin)) {
			return fetch(request, { redirect: "manual" });
		}
		throw new Error(`unmocked CPU measurement egress: ${request.method} ${request.url}`);
	},
};
