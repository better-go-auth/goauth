// Official better-auth client test for goauth's oidc-provider plugin.
// The Go runner (src/tests/compat/oidcproviderclient) starts goauth (BaseURL = GOAUTH_URL) with the
// oidc-provider (loginPage /login, consentPage /consent) and runs this script with:
//   GOAUTH_URL        the goauth server (also its BaseURL / issuer)
//   GOAUTH_OIDC_MODE  "hs256" (id_token signed with the client secret) or "jwt" (jwt plugin, JWKS)
// The script plays the developer (registers a client with oidcClient()), the user's browser (better-auth
// client: sign-in, consent) and the relying party (discovery, token, userinfo, refresh, logout with fetch),
// and verifies the id_token with jose like an OpenID Connect library would.
import { createAuthClient } from "better-auth/client";
import { oidcClient } from "better-auth/client/plugins";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { createHash, randomBytes } from "node:crypto";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const mode = process.env.GOAUTH_OIDC_MODE || "hs256";
const api = `${baseURL}/api/auth`;
const CB = "https://rp.example.com/callback";
const PASSWORD = "Password123!";

console.log(`Running official better-auth/client oidc-provider test (${mode}) against:`, baseURL);

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

// makeClient is a better-auth client with its own cookie jar (one "browser").
function makeClient(headers = {}) {
  const cookies = new Map();
  const getCookieHeader = () => Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
  const saveCookies = (response) => {
    for (const str of response.headers.getSetCookie?.() || []) {
      const [pair] = str.split(";");
      const name = pair.split("=")[0].trim();
      const value = pair.split("=").slice(1).join("=").trim();
      if (str.includes("Max-Age=0") || value === "") cookies.delete(name);
      else cookies.set(name, value);
    }
  };
  const client = createAuthClient({
    baseURL,
    plugins: [oidcClient()],
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", baseURL);
        for (const [k, v] of Object.entries(headers)) ctx.headers.set(k, v);
        const c = getCookieHeader();
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        saveCookies(ctx.response);
      },
    },
  });
  // browserFetch fetches with this browser's cookies, without following redirects. Node's fetch always
  // sends Sec-Fetch-Mode: cors, so the oidc-provider answers like it does to a browser fetch:
  // {redirect: true, url} instead of a 302 (endsession always redirects).
  const browserFetch = async (url, init = {}) => {
    const res = await fetch(url, { redirect: "manual", ...init, headers: { cookie: getCookieHeader(), ...(init.headers || {}) } });
    saveCookies(res);
    return res;
  };
  // navigate returns where a request sends the browser (302 Location, or the {redirect, url} answer)
  const navigate = async (url) => {
    const res = await browserFetch(url);
    if (res.status >= 300 && res.status < 400) return { status: res.status, location: res.headers.get("location") };
    const body = await res.json().catch(() => null);
    return { status: res.status, location: body?.redirect ? body.url : null, body };
  };
  return { client, cookies, browserFetch, navigate };
}

const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function token(params, auth) {
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  if (auth) headers.authorization = "Basic " + Buffer.from(`${encodeURIComponent(auth[0])}:${encodeURIComponent(auth[1])}`).toString("base64");
  const res = await fetch(`${api}/oauth2/token`, { method: "POST", headers, body: new URLSearchParams(params) });
  return { status: res.status, body: await res.json(), headers: res.headers };
}

async function main() {
  // [1] discovery
  console.log("\n[1] discovery...");
  const md = await (await fetch(`${api}/.well-known/openid-configuration`)).json();
  assert(md.issuer === baseURL, `issuer: ${md.issuer}`);
  assert(md.authorization_endpoint === `${api}/oauth2/authorize` && md.token_endpoint === `${api}/oauth2/token`, "endpoints");
  const algs = mode === "jwt" ? "RS256,EdDSA" : "HS256";
  assert(md.id_token_signing_alg_values_supported.join(",") === algs, `algs: ${md.id_token_signing_alg_values_supported}`);

  // [2] a developer registers a client with the better-auth client (oidcClient)
  console.log("\n[2] oauth2.register...");
  const dev = makeClient();
  const su = await dev.client.signUp.email({ email: "dev@example.com", password: PASSWORD, name: "Dev" });
  assert(!su.error, `dev sign-up: ${JSON.stringify(su.error)}`);
  const reg = await dev.client.oauth2.register({ redirect_uris: [CB], client_name: "Node RP", logo_uri: "https://rp.example.com/logo.png" });
  assert(!reg.error && reg.data?.client_id && reg.data.client_secret, `register: ${JSON.stringify(reg)}`);
  const clientId = reg.data.client_id;
  const clientSecret = reg.data.client_secret;
  const info = await dev.client.$fetch(`/oauth2/client/${clientId}`, { method: "GET" });
  assert(info.data?.name === "Node RP" && info.data.icon === "https://rp.example.com/logo.png", `client info: ${JSON.stringify(info)}`);
  const anonReg = await makeClient().client.oauth2.register({ redirect_uris: [CB] });
  assert(anonReg.error?.status === 401, `anonymous register: ${JSON.stringify(anonReg.error)}`);

  // [3] the user's browser: authorize without a session → login page
  console.log("\n[3] authorize → login page...");
  const userSetup = makeClient();
  const us = await userSetup.client.signUp.email({ email: "user@example.com", password: PASSWORD, name: "Node User" });
  assert(!us.error, `user sign-up: ${JSON.stringify(us.error)}`);
  const userId = us.data.user.id;
  const browser = makeClient({ "sec-fetch-mode": "cors" });
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const authURL = `${md.authorization_endpoint}?${new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: CB, scope: "openid profile email offline_access",
    state: "node-state", nonce: "node-nonce", code_challenge: challenge, code_challenge_method: "S256",
  })}`;
  const az = await browser.navigate(authURL);
  assert(az.status === 200 && az.location?.startsWith("/login?response_type=code"), `authorize: ${JSON.stringify(az)}`);
  assert(browser.cookies.has("oidc_login_prompt"), "oidc_login_prompt cookie");

  // [4] signIn.email from the login page resumes the authorization (browser fetch → {redirect, url})
  console.log("\n[4] signIn.email → consent page...");
  const si = await browser.client.signIn.email({ email: "user@example.com", password: PASSWORD });
  assert(!si.error && si.data?.redirect === true && si.data.url.startsWith("/consent?"), `sign-in: ${JSON.stringify(si)}`);
  const consentURL = new URL(si.data.url, baseURL);
  assert(consentURL.searchParams.get("client_id") === clientId, "consent client_id");
  assert(!browser.cookies.has("oidc_login_prompt") && browser.cookies.has("oidc_consent_prompt"), `cookies: ${[...browser.cookies.keys()]}`);

  // [5] oauth2.consent (cookie flow) → redirect URI with code and state
  console.log("\n[5] oauth2.consent...");
  const cs = await browser.client.oauth2.consent({ accept: true });
  assert(!cs.error && cs.data?.redirectURI?.startsWith(`${CB}?code=`), `consent: ${JSON.stringify(cs)}`);
  const redirect = new URL(cs.data.redirectURI);
  assert(redirect.searchParams.get("state") === "node-state", "state");
  const code = redirect.searchParams.get("code");

  // [6] the RP exchanges the code (client_secret_basic + PKCE)
  console.log("\n[6] token...");
  const bad = await token({ grant_type: "authorization_code", code, redirect_uri: CB, code_verifier: "wrong" }, [clientId, clientSecret]);
  assert(bad.status === 401 && bad.body.error === "invalid_request" && bad.body.error_description === "code verification failed", `bad verifier: ${JSON.stringify(bad)}`);
  // the failed exchange consumed the code: authorize again (consent is remembered now)
  const az2 = await browser.navigate(authURL);
  assert(az2.location?.startsWith(`${CB}?code=`), `second authorize: ${JSON.stringify(az2)}`);
  const code2 = new URL(az2.location).searchParams.get("code");
  const tok = await token({ grant_type: "authorization_code", code: code2, redirect_uri: CB, code_verifier: verifier }, [clientId, clientSecret]);
  assert(tok.status === 200 && tok.headers.get("cache-control") === "no-store", `token: ${JSON.stringify(tok.body)}`);
  assert(tok.body.token_type === "Bearer" && tok.body.expires_in === 3600 && tok.body.refresh_token && tok.body.id_token, `token body: ${JSON.stringify(tok.body)}`);
  const reused = await token({ grant_type: "authorization_code", code: code2, redirect_uri: CB, code_verifier: verifier }, [clientId, clientSecret]);
  assert(reused.status === 401 && reused.body.error === "invalid_grant", `reused code: ${JSON.stringify(reused.body)}`);

  // [7] verify the id_token like an OIDC library
  console.log("\n[7] id_token...");
  let payload;
  if (mode === "jwt") {
    ({ payload } = await jwtVerify(tok.body.id_token, createRemoteJWKSet(new URL(md.jwks_uri)), { issuer: md.issuer, audience: clientId }));
  } else {
    ({ payload } = await jwtVerify(tok.body.id_token, new TextEncoder().encode(clientSecret), { audience: clientId, algorithms: ["HS256"] }));
    assert(payload.iss === undefined, "better-auth's HS256 id_token has no iss");
  }
  assert(payload.sub === userId && payload.nonce === "node-nonce" && payload.email === "user@example.com" && payload.given_name === "Node", `claims: ${JSON.stringify(payload)}`);

  // [8] userinfo, refresh
  console.log("\n[8] userinfo + refresh...");
  const ui = await (await fetch(md.userinfo_endpoint, { headers: { authorization: `Bearer ${tok.body.access_token}` } })).json();
  assert(ui.sub === userId && ui.email === "user@example.com" && ui.name === "Node User" && ui.picture === null, `userinfo: ${JSON.stringify(ui)}`);
  const rf = await token({ grant_type: "refresh_token", refresh_token: tok.body.refresh_token, client_id: clientId, client_secret: clientSecret });
  assert(rf.status === 200 && rf.body.access_token && rf.body.access_token !== tok.body.access_token, `refresh: ${JSON.stringify(rf.body)}`);
  const wrong = await token({ grant_type: "refresh_token", refresh_token: tok.body.refresh_token, client_id: clientId, client_secret: "nope" });
  assert(wrong.status === 401 && wrong.body.error === "invalid_client", `wrong secret: ${JSON.stringify(wrong.body)}`);

  // [9] the user denies a new scope set (prompt=consent) → access_denied
  console.log("\n[9] deny...");
  const denyURL = `${md.authorization_endpoint}?${new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: CB, scope: "openid", prompt: "consent" })}`;
  const dz = await browser.client.$fetch(denyURL.replace(api, ""), { method: "GET" });
  assert(dz.data?.redirect === true && dz.data.url.startsWith("/consent?"), `prompt=consent: ${JSON.stringify(dz)}`);
  const deny = await browser.client.oauth2.consent({ accept: false });
  assert(deny.data?.redirectURI === `${CB}?error=access_denied&error_description=User denied access`, `deny: ${JSON.stringify(deny)}`);

  // [10] RP-initiated logout: tokens revoked, session ended, redirect with state
  console.log("\n[10] endsession...");
  const es = await browser.browserFetch(`${md.end_session_endpoint}?${new URLSearchParams({ client_id: clientId, post_logout_redirect_uri: CB, state: "bye" })}`);
  assert(es.status === 302 && es.headers.get("location") === `${CB}?state=bye`, `endsession: ${es.status} ${es.headers.get("location")}`);
  const gone = await fetch(md.userinfo_endpoint, { headers: { authorization: `Bearer ${rf.body.access_token}` } });
  assert(gone.status === 401, `token after logout: ${gone.status}`);
  const sess = await browser.client.getSession();
  assert(!sess.data, `session after logout: ${JSON.stringify(sess.data)}`);

  console.log("\nAll oidc-provider client checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
