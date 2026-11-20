// Runs the official better-auth client with @better-auth/api-key's apiKeyClient() against goauth's api-key
// plugin (started by src/tests/compat/apikeyclient). The server enables metadata and sessions from API keys.
// RATE_KEY is a key the Go test created server-side with rateLimitMax 1.
import { createAuthClient } from "better-auth/client";
import { apiKeyClient, API_KEY_ERROR_CODES } from "@better-auth/api-key/client";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const origin = process.env.PAGE_ORIGIN || baseURL;
const rateKey = process.env.RATE_KEY || "";

console.log("Running official better-auth/client api-key test against:", baseURL);

// makeClient returns a client with its own cookie jar (Node has no browser cookies).
function makeClient() {
	const cookies = new Map();
	const client = createAuthClient({
		baseURL,
		plugins: [apiKeyClient()],
		fetchOptions: {
			onRequest(ctx) {
				ctx.headers.set("origin", origin);
				const c = Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
				if (c) ctx.headers.set("cookie", c);
			},
			onResponse(ctx) {
				for (const str of ctx.response.headers.getSetCookie?.() || []) {
					const [pair] = str.split(";");
					const i = pair.indexOf("=");
					const name = pair.slice(0, i).trim();
					if (str.includes("Max-Age=0")) cookies.delete(name);
					else cookies.set(name, pair.slice(i + 1).trim());
				}
			},
		},
	});
	return client;
}

function assert(cond, msg) {
	if (!cond) {
		console.error("ASSERTION FAILED:", msg);
		process.exit(1);
	}
}

function expectError(res, code, status, label) {
	assert(res.error, `${label}: expected error ${code}, got data ${JSON.stringify(res.data)}`);
	if (code) assert(res.error.code === code, `${label}: expected code ${code}, got ${JSON.stringify(res.error)}`);
	if (status) assert(res.error.status === status, `${label}: expected status ${status}, got ${res.error.status}`);
}

async function main() {
	const client = makeClient();
	const email = `apikey_${Date.now()}@example.com`;

	// 1. sign up (the session cookie authenticates the key routes)
	console.log("\n[1] signUp.email...");
	const signUp = await client.signUp.email({ email, password: "Password123!", name: "Key Owner" });
	assert(!signUp.error, `signUp: ${JSON.stringify(signUp.error)}`);
	const userId = signUp.data.user.id;

	// 2. create a key
	console.log("[2] apiKey.create...");
	const created = await client.apiKey.create({ name: "cli", prefix: "cl_", expiresIn: 2 * 86400, metadata: { tier: "gold" } });
	assert(!created.error, `create: ${JSON.stringify(created.error)}`);
	const key = created.data;
	assert(key.key.startsWith("cl_") && key.key.length === 67, `key value: ${key.key}`);
	assert(key.referenceId === userId && key.configId === "default", `owner: ${JSON.stringify(key)}`);
	assert(key.start === key.key.slice(0, 6) && key.prefix === "cl_", `start/prefix: ${JSON.stringify(key)}`);
	assert(key.metadata.tier === "gold" && key.permissions === null && key.remaining === null, `fields: ${JSON.stringify(key)}`);
	assert(key.rateLimitMax === 10 && key.rateLimitTimeWindow === 86400000 && key.rateLimitEnabled === true, `rate limit: ${JSON.stringify(key)}`);
	assert(new Date(key.expiresAt).getTime() > Date.now() + 86400 * 1000, `expiresAt: ${key.expiresAt}`);

	// 3. server-only properties and bad input are rejected
	console.log("[3] create errors...");
	expectError(await client.apiKey.create({ remaining: 5 }), "SERVER_ONLY_PROPERTY", 400, "remaining");
	expectError(await client.apiKey.create({ permissions: { files: ["read"] } }), "SERVER_ONLY_PROPERTY", 400, "permissions");
	expectError(await client.apiKey.create({ expiresIn: 60 }), "EXPIRES_IN_IS_TOO_SMALL", 400, "expiresIn");
	expectError(await client.apiKey.create({ prefix: "bad prefix" }), "VALIDATION_ERROR", 400, "prefix");
	const tooSmall = await client.apiKey.create({ expiresIn: 60 });
	assert(tooSmall.error.message === API_KEY_ERROR_CODES.EXPIRES_IN_IS_TOO_SMALL.message, `message: ${tooSmall.error.message}`);

	// 4. get: no key value, metadata decoded
	console.log("[4] apiKey.get...");
	const got = await client.apiKey.get({ query: { id: key.id } });
	assert(!got.error, `get: ${JSON.stringify(got.error)}`);
	assert(got.data.id === key.id && got.data.key === undefined && got.data.metadata.tier === "gold", `get data: ${JSON.stringify(got.data)}`);
	expectError(await client.apiKey.get({ query: { id: "missing" } }), "KEY_NOT_FOUND", 404, "get missing");

	// 5. update
	console.log("[5] apiKey.update...");
	const upd = await client.apiKey.update({ keyId: key.id, name: "renamed", metadata: { tier: "silver" } });
	assert(!upd.error && upd.data.name === "renamed" && upd.data.metadata.tier === "silver", `update: ${JSON.stringify(upd)}`);
	expectError(await client.apiKey.update({ keyId: key.id }), "NO_VALUES_TO_UPDATE", 400, "update empty");
	expectError(await client.apiKey.update({ keyId: key.id, remaining: 3 }), "SERVER_ONLY_PROPERTY", 400, "update remaining");

	// 6. list with pagination and sorting
	console.log("[6] apiKey.list...");
	const second = await client.apiKey.create({ name: "second" });
	assert(!second.error, `second: ${JSON.stringify(second.error)}`);
	const all = await client.apiKey.list();
	assert(!all.error && all.data.total === 2 && all.data.apiKeys.length === 2, `list: ${JSON.stringify(all)}`);
	assert(all.data.apiKeys.every((k) => k.key === undefined), "list must not return key values");
	const page = await client.apiKey.list({ query: { limit: 1, offset: 0, sortBy: "name", sortDirection: "desc" } });
	assert(!page.error && page.data.total === 2 && page.data.apiKeys.length === 1 && page.data.apiKeys[0].name === "second" &&
		page.data.limit === 1 && page.data.offset === 0, `page: ${JSON.stringify(page.data)}`);

	// 7. the key is a session (another client without cookies)
	console.log("[7] getSession with x-api-key...");
	const keyClient = makeClient();
	const session = await keyClient.getSession({ fetchOptions: { headers: { "x-api-key": key.key } } });
	assert(!session.error && session.data, `getSession: ${JSON.stringify(session)}`);
	assert(session.data.user.id === userId && session.data.session.id === key.id && session.data.session.token === key.key,
		`session: ${JSON.stringify(session.data)}`);
	const viaKey = await keyClient.apiKey.list({ fetchOptions: { headers: { "x-api-key": key.key } } });
	assert(!viaKey.error && viaKey.data.total === 2, `list via key: ${JSON.stringify(viaKey)}`);
	expectError(await keyClient.getSession({ fetchOptions: { headers: { "x-api-key": "short" } } }), "INVALID_API_KEY", 403, "short key");
	expectError(await keyClient.getSession({ fetchOptions: { headers: { "x-api-key": "x".repeat(64) } } }), "INVALID_API_KEY", 401, "unknown key");
	const anon = await keyClient.getSession();
	assert(!anon.error && anon.data === null, `anonymous session: ${JSON.stringify(anon)}`);

	// 8. per-key rate limit (RATE_KEY allows one request)
	if (rateKey) {
		console.log("[8] rate limit...");
		const first = await keyClient.getSession({ fetchOptions: { headers: { "x-api-key": rateKey } } });
		assert(!first.error && first.data, `first: ${JSON.stringify(first)}`);
		const limited = await keyClient.getSession({ fetchOptions: { headers: { "x-api-key": rateKey } } });
		expectError(limited, "RATE_LIMITED", 429, "rate limited");
		assert(typeof limited.error.details?.tryAgainIn === "number", `details: ${JSON.stringify(limited.error)}`);
	}

	// 9. delete; deleteAllExpiredApiKeys is server-only in 1.6.16 (no route)
	console.log("[9] apiKey.delete...");
	const del = await client.apiKey.delete({ keyId: key.id });
	assert(!del.error && del.data.success === true, `delete: ${JSON.stringify(del)}`);
	expectError(await client.apiKey.get({ query: { id: key.id } }), "KEY_NOT_FOUND", 404, "get deleted");
	expectError(await client.apiKey.delete({ keyId: key.id }), "KEY_NOT_FOUND", 404, "delete twice");
	const expired = await client.apiKey.deleteAllExpiredApiKeys();
	assert(expired.error && expired.error.status === 404, `deleteAllExpiredApiKeys: ${JSON.stringify(expired)}`);

	// 10. without a session the key routes answer 401
	console.log("[10] unauthenticated...");
	const stranger = makeClient();
	expectError(await stranger.apiKey.create({}), "UNAUTHORIZED_SESSION", 401, "create anonymous");
	expectError(await stranger.apiKey.list(), "UNAUTHORIZED", 401, "list anonymous");

	console.log("\nAll api-key client checks passed.");
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
