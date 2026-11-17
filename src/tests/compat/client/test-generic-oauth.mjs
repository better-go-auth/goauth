// Official better-auth client test for goauth's generic-oauth plugin.
// The Go runner (src/tests/compat/genericoauthclient) starts a fake OAuth2/OIDC provider and goauth with the
// generic-oauth providers "fake" (explicit endpoints, PKCE, basic auth) and "disc" (OIDC discovery) pointed at
// it, then runs this script with:
//   GOAUTH_URL             the goauth test server
//   GOAUTH_APP_BASE        goauth's configured BaseURL (callback URLs / redirect_uri use it)
//   GOAUTH_PROVIDER_EMAIL  the email of the fake provider's user
import { createAuthClient } from "better-auth/client";
import { genericOAuthClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const appBase = process.env.GOAUTH_APP_BASE || "http://localhost:3000";
const providerEmail = process.env.GOAUTH_PROVIDER_EMAIL || "fake.user@example.com";

console.log("Running official better-auth/client generic-oauth test against:", baseURL);

function makeClient(url) {
  const cookies = new Map();

  function getCookieHeader() {
    return Array.from(cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }

  function saveCookies(response) {
    const getSetCookie = response.headers.getSetCookie?.() || [];
    if (getSetCookie.length === 0) {
      const raw = response.headers.get("set-cookie");
      if (raw) getSetCookie.push(raw);
    }
    for (const str of getSetCookie) {
      const parts = str.split(";")[0].split("=");
      const name = parts[0]?.trim();
      const value = parts.slice(1).join("=").trim();
      if (name) {
        if (str.includes("Max-Age=0") || /Max-Age=-/.test(str) || value === "") cookies.delete(name);
        else cookies.set(name, value);
      }
    }
  }

  const client = createAuthClient({
    baseURL: url,
    plugins: [genericOAuthClient()],
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", url);
        const c = getCookieHeader();
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        saveCookies(ctx.response);
      },
    },
  });

  return { client, cookies, saveCookies, getCookieHeader };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

// followOAuth walks the browser part of the flow: provider authorize → goauth /oauth2/callback.
// It returns the callback response (a 302 to the app).
async function followOAuth(c, authURL) {
  const authRes = await fetch(authURL, { redirect: "manual" });
  assert(authRes.status === 302, `provider authorize should redirect, got ${authRes.status}`);
  const callbackURL = authRes.headers.get("location");
  assert(callbackURL && callbackURL.startsWith(`${baseURL}/api/auth/oauth2/callback/`), `provider should redirect to goauth, got ${callbackURL}`);
  const cbRes = await fetch(callbackURL, {
    redirect: "manual",
    headers: { cookie: c.getCookieHeader() },
  });
  c.saveCookies(cbRes);
  return cbRes;
}

function sessionCookieName(c) {
  return Array.from(c.cookies.keys()).find((k) => k.endsWith("session_token"));
}

async function main() {
  const c = makeClient(baseURL);
  const { client } = c;

  // 0. the client plugin ships better-auth's error codes
  assert(client.$ERROR_CODES?.PROVIDER_CONFIG_NOT_FOUND, "genericOAuthClient error codes missing");

  // 1. signIn.oauth2 with disableRedirect → authorization URL + state cookie
  console.log("\n[1] signIn.oauth2 (redirect flow)...");
  const start = await client.signIn.oauth2({
    providerId: "fake",
    callbackURL: `${appBase}/dashboard`,
    newUserCallbackURL: `${appBase}/welcome`,
    errorCallbackURL: `${appBase}/oops`,
    scopes: ["extra"],
    disableRedirect: true,
  });
  assert(!start.error, `signIn.oauth2 failed: ${JSON.stringify(start.error)}`);
  assert(start.data?.url && start.data.redirect === false, `unexpected signIn.oauth2 data: ${JSON.stringify(start.data)}`);
  const authURL = new URL(start.data.url);
  assert(authURL.searchParams.get("code_challenge_method") === "S256", "PKCE S256 missing");
  assert(authURL.searchParams.get("scope") === "extra openid email profile", `scope: ${authURL.searchParams.get("scope")}`);
  assert(authURL.searchParams.get("redirect_uri") === `${appBase}/api/auth/oauth2/callback/fake`, `redirect_uri: ${authURL.searchParams.get("redirect_uri")}`);
  assert(Array.from(c.cookies.keys()).some((k) => k.endsWith(".state")), "state cookie not stored");

  // 2. provider → callback: new user lands on newUserCallbackURL with a session cookie
  console.log("\n[2] provider authorize → /oauth2/callback/fake ...");
  const cb = await followOAuth(c, start.data.url);
  assert(cb.status === 302, `callback should redirect, got ${cb.status}`);
  assert(cb.headers.get("location") === `${appBase}/welcome`, `new user redirect: ${cb.headers.get("location")}`);
  assert(sessionCookieName(c), "no session cookie after callback");

  // 3. the session is usable by the client
  console.log("\n[3] getSession...");
  const sess = await client.getSession();
  assert(!sess.error && sess.data?.user?.email === providerEmail, `getSession: ${JSON.stringify(sess)}`);
  assert(sess.data.user.emailVerified === true, "provider-verified email should be verified");

  // 4. listAccounts shows the provider account
  console.log("\n[4] listAccounts...");
  const accs = await client.listAccounts();
  assert(!accs.error, `listAccounts: ${JSON.stringify(accs.error)}`);
  const fakeAcc = accs.data.find((a) => a.providerId === "fake");
  assert(fakeAcc && fakeAcc.scopes.includes("openid"), `fake account missing: ${JSON.stringify(accs.data)}`);

  // 5. second sign-in goes to callbackURL (existing user)
  console.log("\n[5] second sign-in...");
  const again = await client.signIn.oauth2({ providerId: "fake", callbackURL: `${appBase}/dashboard`, newUserCallbackURL: `${appBase}/welcome`, disableRedirect: true });
  assert(!again.error, `second signIn.oauth2: ${JSON.stringify(again.error)}`);
  const cb2 = await followOAuth(c, again.data.url);
  assert(cb2.headers.get("location") === `${appBase}/dashboard`, `existing user redirect: ${cb2.headers.get("location")}`);

  // 6. oauth2.link with the discovery provider
  console.log("\n[6] oauth2.link (disc, OIDC discovery)...");
  const link = await client.oauth2.link({ providerId: "disc", callbackURL: `${appBase}/linked` });
  assert(!link.error && link.data?.url && link.data.redirect === true, `oauth2.link: ${JSON.stringify(link)}`);
  assert(new URL(link.data.url).searchParams.get("redirect_uri") === `${appBase}/api/auth/oauth2/callback/disc`, `link redirect_uri: ${link.data.url}`);
  const cb3 = await followOAuth(c, link.data.url);
  assert(cb3.status === 302 && cb3.headers.get("location") === `${appBase}/linked`, `link callback: ${cb3.status} ${cb3.headers.get("location")}`);
  const accs2 = await client.listAccounts();
  assert(accs2.data.some((a) => a.providerId === "disc"), `disc not linked: ${JSON.stringify(accs2.data)}`);

  // 7. errors: unknown provider, untrusted callbackURL, link without session, state mismatch
  console.log("\n[7] error cases...");
  const unknown = await client.signIn.oauth2({ providerId: "nope", disableRedirect: true });
  assert(unknown.error?.status === 400 && unknown.error.message === "No config found for provider nope", `unknown provider: ${JSON.stringify(unknown.error)}`);
  const bad = await client.signIn.oauth2({ providerId: "fake", callbackURL: "https://evil.example.com/x", disableRedirect: true });
  assert(bad.error?.status === 403 && bad.error.code === "INVALID_CALLBACK_URL", `untrusted callbackURL: ${JSON.stringify(bad.error)}`);
  const anon = makeClient(baseURL);
  const noSession = await anon.client.oauth2.link({ providerId: "fake", callbackURL: "/x" });
  assert(noSession.error?.status === 401, `link without session: ${JSON.stringify(noSession.error)}`);
  const mismatch = await fetch(`${baseURL}/api/auth/oauth2/callback/fake?code=x&state=forged`, { redirect: "manual" });
  assert(mismatch.status === 302 && mismatch.headers.get("location") === `${appBase}/api/auth/error?error=state_mismatch`, `state mismatch: ${mismatch.headers.get("location")}`);
  const denied = await fetch(`${baseURL}/api/auth/oauth2/callback/fake?error=access_denied&state=x`, { redirect: "manual" });
  assert(denied.status === 302 && denied.headers.get("location") === `${appBase}/api/auth/error?error=access_denied`, `provider error: ${denied.headers.get("location")}`);

  // 8. sign out
  const out = await client.signOut();
  assert(!out.error, `signOut: ${JSON.stringify(out.error)}`);
  const after = await client.getSession();
  assert(!after.data, `session should be gone: ${JSON.stringify(after.data)}`);

  console.log("\nAll generic-oauth client checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
