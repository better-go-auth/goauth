// Official better-auth client test for goauth's mcp plugin.
// The Go runner (src/tests/compat/mcpclient) starts goauth (BaseURL = GOAUTH_URL) with the mcp plugin
// (loginPage /login), an MCP endpoint at /mcp protected with WithMcpAuth and the discovery helpers at the
// origin, then runs this script with GOAUTH_URL. The script is an MCP client (discovery from the 401,
// dynamic registration, authorization code + PKCE, token, refresh) and checks the MCP resource-server side
// with better-auth's own createMcpAuthClient (better-auth/plugins/mcp/client), which calls /mcp/get-session.
import { createAuthClient } from "better-auth/client";
import { createMcpAuthClient } from "better-auth/plugins/mcp/client";
import { createHash, randomBytes } from "node:crypto";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const api = `${baseURL}/api/auth`;
const CB = "http://localhost:6274/oauth/callback";
const PASSWORD = "Password123!";

console.log("Running official better-auth mcp test against:", baseURL);

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// a browser: cookie jar + fetch without redirect following
function makeBrowser() {
  const cookies = new Map();
  const header = () => Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
  const go = async (url, init = {}) => {
    const res = await fetch(url, { redirect: "manual", ...init, headers: { cookie: header(), origin: baseURL, ...(init.headers || {}) } });
    for (const str of res.headers.getSetCookie?.() || []) {
      const [pair] = str.split(";");
      const name = pair.split("=")[0].trim();
      const value = pair.split("=").slice(1).join("=").trim();
      if (str.includes("Max-Age=0") || value === "") cookies.delete(name);
      else cookies.set(name, value);
    }
    return res;
  };
  return { cookies, go };
}

async function tokenRequest(params) {
  const res = await fetch(`${api}/mcp/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
  });
  return { status: res.status, body: await res.json() };
}

async function main() {
  // [1] the MCP server answers 401 and points at the protected resource metadata
  console.log("\n[1] 401 + discovery...");
  const unauth = await fetch(`${baseURL}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }) });
  const www = unauth.headers.get("www-authenticate");
  assert(unauth.status === 401 && www === `Bearer resource_metadata="${api}/.well-known/oauth-protected-resource"`, `401: ${unauth.status} ${www}`);
  const err = await unauth.json();
  assert(err.jsonrpc === "2.0" && err.error.code === -32000 && err.id === null, `401 body: ${JSON.stringify(err)}`);
  const prm = await (await fetch(www.match(/resource_metadata="([^"]+)"/)[1])).json();
  assert(prm.authorization_servers?.[0] === baseURL && prm.resource === baseURL, `protected resource: ${JSON.stringify(prm)}`);
  const asm = await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json();
  assert(asm.issuer === baseURL && asm.registration_endpoint === `${api}/mcp/register` && asm.code_challenge_methods_supported.includes("S256"), `AS metadata: ${JSON.stringify(asm)}`);

  // [2] dynamic registration of a public client
  console.log("\n[2] register...");
  const regRes = await fetch(asm.registration_endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Node MCP client", redirect_uris: [CB], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"] }),
  });
  const reg = await regRes.json();
  assert(regRes.status === 201 && reg.client_id && reg.client_secret === undefined && regRes.headers.get("access-control-allow-origin") === "*", `register: ${JSON.stringify(reg)}`);

  // [3] the user signs up (better-auth client), then authorizes in a fresh browser
  console.log("\n[3] authorize → login → resume...");
  const auth = createAuthClient({ baseURL, fetchOptions: { headers: { origin: baseURL } } });
  const su = await auth.signUp.email({ email: "mcp.user@example.com", password: PASSWORD, name: "Mcp User" });
  assert(!su.error, `sign-up: ${JSON.stringify(su.error)}`);
  const browser = makeBrowser();
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const authURL = `${asm.authorization_endpoint}?${new URLSearchParams({
    response_type: "code", client_id: reg.client_id, redirect_uri: CB, scope: "openid profile email offline_access",
    state: "mcp-state", code_challenge: challenge, code_challenge_method: "S256",
  })}`;
  const az = await browser.go(authURL);
  assert(az.status === 302 && az.headers.get("location").startsWith("/login?"), `authorize: ${az.status} ${az.headers.get("location")}`);
  assert(az.headers.get("access-control-allow-origin") === "*", "authorize CORS");
  const si = await browser.go(`${api}/sign-in/email`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "mcp.user@example.com", password: PASSWORD }) });
  const back = si.headers.get("location") || "";
  assert(si.status === 302 && back.startsWith(`${CB}?code=`), `sign-in resume: ${si.status} ${back}`);
  const cb = new URL(back);
  assert(cb.searchParams.get("state") === "mcp-state", "state");

  // [4] token (PKCE, no secret)
  console.log("\n[4] token...");
  const tok = await tokenRequest({ grant_type: "authorization_code", code: cb.searchParams.get("code"), redirect_uri: CB, client_id: reg.client_id, code_verifier: verifier });
  assert(tok.status === 200 && tok.body.access_token && tok.body.refresh_token && tok.body.token_type === "Bearer", `token: ${JSON.stringify(tok)}`);

  // [5] better-auth's MCP resource-server client validates the token through /mcp/get-session
  console.log("\n[5] createMcpAuthClient...");
  const mcpAuth = createMcpAuthClient({ authURL: api });
  const session = await mcpAuth.verifyToken(tok.body.access_token);
  assert(session?.userId === su.data.user.id && session.clientId === reg.client_id && session.scopes === "openid profile email offline_access", `verifyToken: ${JSON.stringify(session)}`);
  assert((await mcpAuth.verifyToken("not-a-token")) === null, "unknown token must not verify");
  const handler = mcpAuth.handler(async (_req, s) => Response.json({ userId: s.userId }));
  const ok = await handler(new Request("http://mcp.local/mcp", { method: "POST", headers: { authorization: `Bearer ${tok.body.access_token}` } }));
  assert(ok.status === 200 && (await ok.json()).userId === su.data.user.id, "handler with token");
  const denied = await handler(new Request("http://mcp.local/mcp", { method: "POST" }));
  assert(denied.status === 401 && denied.headers.get("www-authenticate")?.includes("resource_metadata="), "handler without token");

  // [6] the goauth-protected MCP endpoint (WithMcpAuth)
  console.log("\n[6] MCP call...");
  const call = await fetch(`${baseURL}/mcp`, { method: "POST", headers: { authorization: `Bearer ${tok.body.access_token}`, "content-type": "application/json" }, body: "{}" });
  const callBody = await call.json();
  assert(call.status === 200 && callBody.result?.userId === su.data.user.id, `mcp call: ${JSON.stringify(callBody)}`);

  // [7] refresh
  console.log("\n[7] refresh...");
  const rf = await tokenRequest({ grant_type: "refresh_token", refresh_token: tok.body.refresh_token, client_id: reg.client_id });
  assert(rf.status === 200 && rf.body.token_type === "bearer" && rf.body.access_token !== tok.body.access_token, `refresh: ${JSON.stringify(rf)}`);
  const reused = await tokenRequest({ grant_type: "authorization_code", code: cb.searchParams.get("code"), redirect_uri: CB, client_id: reg.client_id, code_verifier: verifier });
  assert(reused.status === 401 && reused.body.error === "invalid_grant", `reused code: ${JSON.stringify(reused)}`);

  console.log("\nAll mcp client checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
