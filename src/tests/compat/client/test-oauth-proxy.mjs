// Official better-auth client test for goauth's oauth-proxy plugin.
// The Go runner (src/tests/compat/oauthproxyclient) starts a fake OAuth2/OIDC provider, a production goauth
// deployment (BaseURL GOAUTH_PRODUCTION_BASE, served at GOAUTH_PRODUCTION_URL) and a preview deployment
// (GOAUTH_URL) whose oauthProxy productionURL is the production base. Both use the secret GOAUTH_SECRET.
// The script drives signIn.social with the official client on the preview and follows the redirects like a
// browser; it also checks that better-auth's own symmetricEncrypt/Decrypt interoperate with goauth's payloads.
import { createAuthClient } from "better-auth/client";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";

const previewURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const productionBase = process.env.GOAUTH_PRODUCTION_BASE || "http://localhost:3000";
const productionURL = process.env.GOAUTH_PRODUCTION_URL || productionBase;
const secret = process.env.GOAUTH_SECRET || "";
const providerEmail = process.env.GOAUTH_PROVIDER_EMAIL || "fake.user@example.com";

console.log("Running official better-auth/client oauth-proxy test against preview:", previewURL);

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

function makeClient(url) {
  const cookies = new Map();
  const getCookieHeader = () =>
    Array.from(cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  const saveCookies = (response) => {
    for (const str of response.headers.getSetCookie?.() || []) {
      const [pair] = str.split(";");
      const idx = pair.indexOf("=");
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      if (str.includes("Max-Age=0") || /Max-Age=-/.test(str) || value === "") cookies.delete(name);
      else cookies.set(name, value);
    }
  };
  const client = createAuthClient({
    baseURL: url,
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
  return { client, cookies, getCookieHeader, saveCookies };
}

async function main() {
  const c = makeClient(previewURL);
  const { client } = c;

  // 1. signIn.social on the preview: production's redirect_uri and an encrypted state package
  console.log("\n[1] signIn.social on the preview...");
  const start = await client.signIn.social({ provider: "fake", callbackURL: "/dashboard", disableRedirect: true });
  assert(!start.error && start.data?.url, `signIn.social failed: ${JSON.stringify(start.error)}`);
  const authURL = new URL(start.data.url);
  assert(
    authURL.searchParams.get("redirect_uri") === `${productionBase}/api/auth/callback/fake`,
    `redirect_uri should be production's callback: ${authURL.searchParams.get("redirect_uri")}`,
  );
  const pkg = JSON.parse(await symmetricDecrypt({ key: secret, data: authURL.searchParams.get("state") }));
  assert(pkg.isOAuthProxy === true && pkg.state && pkg.stateCookie, `state package: ${JSON.stringify(pkg)}`);
  const stateData = JSON.parse(await symmetricDecrypt({ key: secret, data: pkg.stateCookie }));
  assert(
    stateData.callbackURL === `${previewURL}/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard`,
    `rewritten callbackURL: ${stateData.callbackURL}`,
  );
  assert(stateData.oauthState === pkg.state, "state package must carry the preview's state");

  // 2. provider → production callback → preview proxy callback with the encrypted profile
  console.log("\n[2] provider → production /callback/fake ...");
  const authRes = await fetch(authURL, { redirect: "manual" });
  assert(authRes.status === 302, `provider authorize should redirect, got ${authRes.status}`);
  const prodCallback = authRes.headers.get("location");
  assert(prodCallback.startsWith(`${productionURL}/api/auth/callback/fake?`), `provider redirect: ${prodCallback}`);
  const prodRes = await fetch(prodCallback, { redirect: "manual" });
  assert(prodRes.status === 302, `production callback should redirect, got ${prodRes.status}`);
  assert(prodRes.headers.getSetCookie().length === 0, "production must not set cookies");
  const proxyURL = new URL(prodRes.headers.get("location"));
  assert(proxyURL.href.startsWith(`${previewURL}/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile=`), `production redirect: ${proxyURL}`);
  const profile = JSON.parse(await symmetricDecrypt({ key: secret, data: proxyURL.searchParams.get("profile") }));
  assert(
    profile.userInfo.email === providerEmail && profile.account.providerId === "fake" && profile.state === pkg.state &&
      typeof profile.timestamp === "number" && profile.callbackURL === "/dashboard",
    `profile payload: ${JSON.stringify(profile)}`,
  );

  // 3. the preview signs the user in and redirects to the original callbackURL
  console.log("\n[3] preview /oauth-proxy-callback ...");
  const prevRes = await fetch(proxyURL, { redirect: "manual", headers: { cookie: c.getCookieHeader() } });
  c.saveCookies(prevRes);
  assert(prevRes.status === 302 && prevRes.headers.get("location") === "/dashboard", `proxy callback: ${prevRes.status} ${prevRes.headers.get("location")}`);
  const sess = await client.getSession();
  assert(!sess.error && sess.data?.user?.email === providerEmail, `getSession: ${JSON.stringify(sess)}`);
  const accounts = await client.listAccounts();
  assert(!accounts.error && accounts.data.some((a) => a.providerId === "fake"), `listAccounts: ${JSON.stringify(accounts)}`);

  // 4. a profile encrypted by better-auth itself (a TypeScript production deployment) is accepted
  console.log("\n[4] profile encrypted with better-auth's symmetricEncrypt...");
  const ts = makeClient(previewURL);
  const tsProfile = await symmetricEncrypt({
    key: secret,
    data: JSON.stringify({
      userInfo: { id: "ts-user", email: "TS.User@example.com", name: "TS User", emailVerified: true },
      account: { providerId: "fake", accountId: "ts-user", accessToken: "ts-access", scope: "openid,email" },
      state: "state-from-ts",
      callbackURL: "/from-ts",
      newUserURL: "/welcome-ts",
      timestamp: Date.now(),
    }),
  });
  const tsURL = `${previewURL}/api/auth/oauth-proxy-callback?callbackURL=${encodeURIComponent("/from-ts")}&profile=${tsProfile}`;
  const tsRes = await fetch(tsURL, { redirect: "manual" });
  ts.saveCookies(tsRes);
  assert(tsRes.status === 302 && tsRes.headers.get("location") === "/welcome-ts", `TS profile: ${tsRes.status} ${tsRes.headers.get("location")}`);
  const tsSess = await ts.client.getSession();
  assert(tsSess.data?.user?.email === "ts.user@example.com", `TS session: ${JSON.stringify(tsSess)}`);

  // 5. error redirects and the callbackURL origin check
  console.log("\n[5] errors...");
  const missing = await fetch(`${previewURL}/api/auth/oauth-proxy-callback?callbackURL=%2Fx`, { redirect: "manual" });
  assert(missing.status === 302 && new URL(missing.headers.get("location")).searchParams.get("error") === "missing_profile", `missing profile: ${missing.headers.get("location")}`);
  const expired = await symmetricEncrypt({
    key: secret,
    data: JSON.stringify({ userInfo: {}, account: {}, callbackURL: "/x", errorURL: "/err", timestamp: Date.now() - 120_000 }),
  });
  const expRes = await fetch(`${previewURL}/api/auth/oauth-proxy-callback?callbackURL=%2Fx&profile=${expired}`, { redirect: "manual" });
  assert(expRes.headers.get("location") === "/err?error=payload_expired", `expired: ${expRes.headers.get("location")}`);
  const untrusted = await client.$fetch("/oauth-proxy-callback", {
    method: "GET",
    query: { callbackURL: "https://evil.example.com", profile: tsProfile },
  });
  assert(untrusted.error?.status === 403 && untrusted.error?.code === "INVALID_CALLBACK_URL", `untrusted callbackURL: ${JSON.stringify(untrusted.error)}`);

  // 6. x-skip-oauth-proxy keeps the normal flow on the preview
  console.log("\n[6] x-skip-oauth-proxy...");
  const skip = await client.signIn.social(
    { provider: "fake", callbackURL: "/home", disableRedirect: true },
    { headers: { "x-skip-oauth-proxy": "true" } },
  );
  const skipURL = new URL(skip.data.url);
  assert(skipURL.searchParams.get("state").length === 32, "skip: state must be the plain state");
  assert(!skipURL.searchParams.get("redirect_uri").startsWith(productionBase), `skip: redirect_uri ${skipURL.searchParams.get("redirect_uri")}`);

  console.log("\nAll oauth-proxy client checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
