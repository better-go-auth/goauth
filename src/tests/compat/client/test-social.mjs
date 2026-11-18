// Official better-auth client test for goauth's social sign-in plugin.
// The Go runner (src/tests/compat/socialclient) starts a fake OAuth2/OIDC provider and goauth with the
// generic providers "fake" and "fake2" pointed at it, then runs this script with:
//   GOAUTH_URL       the goauth test server
//   GOAUTH_APP_BASE  goauth's configured BaseURL (callback URLs / redirect_uri use it)
//   GOAUTH_ID_TOKEN  an id_token signed by the fake provider (for id_token sign-in)
//   GOAUTH_ID_EMAIL  the email inside GOAUTH_ID_TOKEN
//   GOAUTH_ACCOUNT_COOKIE  "1" when goauth runs with account.storeAccountCookie (socialProviders configured in
//                          core, src/tests/compat/socialcoreclient): accountInfo() then works without accountId
import { createAuthClient } from "better-auth/client";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const appBase = process.env.GOAUTH_APP_BASE || "http://localhost:3000";
const idToken = process.env.GOAUTH_ID_TOKEN || "";
const idEmail = process.env.GOAUTH_ID_EMAIL || "";
const providerEmail = process.env.GOAUTH_PROVIDER_EMAIL || "fake.user@example.com";
const accountCookie = process.env.GOAUTH_ACCOUNT_COOKIE === "1";

console.log("Running official better-auth/client social sign-in test against:", baseURL);

function makeClient(url) {
  let bearerToken = "";
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
    fetchOptions: {
      auth: {
        type: "Bearer",
        token: () => bearerToken,
      },
      onRequest(ctx) {
        ctx.headers.set("origin", url);
        const c = getCookieHeader();
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        saveCookies(ctx.response);
        const tok = ctx.response.headers.get("set-auth-token");
        if (tok) bearerToken = tok;
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

// followOAuth walks the browser part of the flow: provider authorize → goauth callback.
// It returns the callback response (a 302 to the app).
async function followOAuth(c, authURL) {
  const authRes = await fetch(authURL, { redirect: "manual" });
  assert(authRes.status === 302, `provider authorize should redirect, got ${authRes.status}`);
  const callbackURL = authRes.headers.get("location");
  assert(callbackURL && callbackURL.startsWith(baseURL), `provider should redirect to goauth, got ${callbackURL}`);
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

  // 1. signIn.social with disableRedirect → authorization URL + state cookie
  console.log("\n[1] signIn.social (redirect flow)...");
  const start = await client.signIn.social({
    provider: "fake",
    callbackURL: `${appBase}/dashboard`,
    newUserCallbackURL: `${appBase}/welcome`,
    errorCallbackURL: `${appBase}/oops`,
    disableRedirect: true,
  });
  assert(!start.error, `signIn.social failed: ${JSON.stringify(start.error)}`);
  assert(start.data?.url && start.data.redirect === false, `unexpected signIn.social data: ${JSON.stringify(start.data)}`);
  const authURL = new URL(start.data.url);
  assert(authURL.searchParams.get("code_challenge_method") === "S256", "PKCE S256 missing");
  assert(authURL.searchParams.get("redirect_uri") === `${appBase}/api/auth/callback/fake`, `redirect_uri: ${authURL.searchParams.get("redirect_uri")}`);
  assert(Array.from(c.cookies.keys()).some((k) => k.endsWith(".state")), "state cookie not stored");

  // 2. provider → callback: new user lands on newUserCallbackURL with a session cookie
  console.log("\n[2] provider authorize → /callback/fake ...");
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

  // 5. getAccessToken / refreshToken / accountInfo
  console.log("\n[5] getAccessToken / refreshToken / accountInfo...");
  const at = await client.getAccessToken({ providerId: "fake" });
  assert(!at.error && at.data?.accessToken?.startsWith("at-"), `getAccessToken: ${JSON.stringify(at)}`);
  assert(Array.isArray(at.data.scopes) && at.data.idToken, `getAccessToken shape: ${JSON.stringify(at.data)}`);
  const rt = await client.refreshToken({ providerId: "fake" });
  assert(!rt.error && rt.data?.accessToken && rt.data.accessToken !== at.data.accessToken, `refreshToken: ${JSON.stringify(rt)}`);
  assert(rt.data.providerId === "fake" && rt.data.accountId === fakeAcc.accountId, `refreshToken ids: ${JSON.stringify(rt.data)}`);
  const at2 = await client.getAccessToken({ providerId: "fake" });
  assert(at2.data?.accessToken === rt.data.accessToken, "getAccessToken should return the refreshed token");
  const info = await client.accountInfo({ query: { accountId: fakeAcc.accountId } });
  assert(!info.error && info.data?.user?.email === providerEmail && info.data?.data, `accountInfo: ${JSON.stringify(info)}`);
  if (accountCookie) {
    // account.storeAccountCookie: the encrypted account_data cookie identifies the account
    assert(Array.from(c.cookies.keys()).some((k) => k.endsWith("account_data")), "account_data cookie not stored");
    const fromCookie = await client.accountInfo();
    assert(!fromCookie.error && fromCookie.data?.user?.email === providerEmail, `accountInfo without accountId: ${JSON.stringify(fromCookie)}`);
  } else {
    const noCookie = await client.accountInfo();
    assert(noCookie.error?.status === 400 && noCookie.error.code === "ACCOUNT_NOT_FOUND", `accountInfo without accountId: ${JSON.stringify(noCookie)}`);
  }

  // 6. second sign-in goes to callbackURL (existing user)
  console.log("\n[6] second sign-in...");
  const again = await client.signIn.social({ provider: "fake", callbackURL: `${appBase}/dashboard`, newUserCallbackURL: `${appBase}/welcome`, disableRedirect: true });
  const cb2 = await followOAuth(c, again.data.url);
  assert(cb2.headers.get("location") === `${appBase}/dashboard`, `existing user redirect: ${cb2.headers.get("location")}`);

  // 7. linkSocial with a second provider
  console.log("\n[7] linkSocial (fake2)...");
  const link = await client.linkSocial({ provider: "fake2", callbackURL: `${appBase}/linked`, disableRedirect: true });
  assert(!link.error && link.data?.url && link.data.redirect === false, `linkSocial: ${JSON.stringify(link)}`);
  const cb3 = await followOAuth(c, link.data.url);
  assert(cb3.status === 302 && cb3.headers.get("location") === `${appBase}/linked`, `link callback: ${cb3.status} ${cb3.headers.get("location")}`);
  const accs2 = await client.listAccounts();
  assert(accs2.data.some((a) => a.providerId === "fake2"), `fake2 not linked: ${JSON.stringify(accs2.data)}`);

  // 8. errors: untrusted callbackURL, unknown provider, state mismatch
  console.log("\n[8] error cases...");
  const bad = await client.signIn.social({ provider: "fake", callbackURL: "https://evil.example.com/x", disableRedirect: true });
  assert(bad.error?.status === 403 && bad.error.code === "INVALID_CALLBACK_URL", `untrusted callbackURL: ${JSON.stringify(bad.error)}`);
  const unknown = await client.signIn.social({ provider: "nope", disableRedirect: true });
  assert(unknown.error?.status === 404 && unknown.error.code === "PROVIDER_NOT_FOUND", `unknown provider: ${JSON.stringify(unknown.error)}`);
  const mismatch = await fetch(`${baseURL}/api/auth/callback/fake?code=x&state=forged`, { redirect: "manual" });
  assert(mismatch.status === 302 && mismatch.headers.get("location") === `${appBase}/api/auth/error?error=state_mismatch`, `state mismatch: ${mismatch.headers.get("location")}`);

  // 9. id_token sign-in in a fresh client
  if (idToken) {
    console.log("\n[9] signIn.social with idToken...");
    const c2 = makeClient(baseURL);
    const res = await c2.client.signIn.social({ provider: "fake", idToken: { token: idToken } });
    assert(!res.error && res.data?.redirect === false && res.data?.token && res.data?.user?.email === idEmail, `idToken sign-in: ${JSON.stringify(res)}`);
    const s2 = await c2.client.getSession();
    assert(s2.data?.user?.email === idEmail, `idToken session: ${JSON.stringify(s2)}`);
    const badTok = await c2.client.signIn.social({ provider: "fake", idToken: { token: idToken + "x" } });
    assert(badTok.error?.status === 401 && badTok.error.code === "INVALID_TOKEN", `bad idToken: ${JSON.stringify(badTok.error)}`);
  }

  // 10. sign out (also drops the account_data cookie with storeAccountCookie)
  const out = await client.signOut();
  assert(!out.error, `signOut: ${JSON.stringify(out.error)}`);
  assert(!Array.from(c.cookies.keys()).some((k) => k.endsWith("account_data")), "account_data cookie must be deleted on sign-out");

  console.log("\nAll social sign-in client checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
