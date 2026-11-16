import { createAuthClient } from "better-auth/client";
import { magicLinkClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const appOrigin = process.env.GOAUTH_APP_ORIGIN || "http://localhost:3000";

console.log("Running official better-auth/client magic-link test against:", baseURL);

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
        if (str.includes("Max-Age=0")) cookies.delete(name);
        else cookies.set(name, value);
      }
    }
  }

  const client = createAuthClient({
    baseURL: url,
    plugins: [magicLinkClient()],
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

  return { client, cookies, saveCookies };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

async function fetchLastLink(email) {
  const res = await fetch(`${baseURL}/test/last-magic-link?email=${encodeURIComponent(email)}`);
  assert(res.ok, `failed to fetch test magic link for ${email}: ${res.status}`);
  return res.json();
}

async function main() {
  const ts = Date.now();

  // 1. signIn.magicLink sends a link in better-auth's URL format
  console.log("\n[1] signIn.magicLink (new user)...");
  const { client } = makeClient(baseURL);
  const email = `magic-${ts}@example.com`;
  const sent = await client.signIn.magicLink({ email, name: "Magic User" });
  assert(!sent.error && sent.data?.status === true, `signIn.magicLink failed: ${JSON.stringify(sent)}`);
  const link1 = await fetchLastLink(email);
  assert(/^[a-zA-Z]{32}$/.test(link1.token), `unexpected token format: ${link1.token}`);
  const url1 = new URL(link1.url);
  assert(url1.origin === appOrigin, `link origin ${url1.origin} !== ${appOrigin}`);
  assert(url1.pathname === "/api/auth/magic-link/verify", `link path: ${url1.pathname}`);
  assert(url1.searchParams.get("token") === link1.token, "token param mismatch");
  assert(url1.searchParams.get("callbackURL") === "/", `default callbackURL: ${url1.searchParams.get("callbackURL")}`);

  // 2. magicLink.verify without callbackURL returns {token, user, session} and sets the cookie
  console.log("\n[2] magicLink.verify (JSON response)...");
  const verified = await client.magicLink.verify({ query: { token: link1.token } });
  assert(!verified.error, `verify failed: ${JSON.stringify(verified.error)}`);
  const v = verified.data;
  assert(v?.token && v.session?.token === v.token, `token/session mismatch: ${JSON.stringify(v)}`);
  assert(v.user?.email === email && v.user?.name === "Magic User" && v.user?.emailVerified === true,
    `unexpected user: ${JSON.stringify(v.user)}`);

  // 3. getSession sees the new session
  console.log("\n[3] getSession...");
  const session = await client.getSession();
  assert(!session.error && session.data?.user?.id === v.user.id, `getSession failed: ${JSON.stringify(session)}`);

  // 4. tokens are single use
  console.log("\n[4] reusing the token...");
  const reuse = await fetch(`${baseURL}/api/auth/magic-link/verify?token=${link1.token}`, { redirect: "manual" });
  assert(reuse.status === 302, `reuse: expected 302, got ${reuse.status}`);
  assert(reuse.headers.get("location") === `${appOrigin}/?error=INVALID_TOKEN`,
    `reuse location: ${reuse.headers.get("location")}`);

  // 5. callbackURL / newUserCallbackURL redirects with the session cookie
  console.log("\n[5] callbackURL redirects...");
  const email2 = `magic-redirect-${ts}@example.com`;
  const sent2 = await client.signIn.magicLink({ email: email2, callbackURL: "/dashboard", newUserCallbackURL: "/welcome" });
  assert(!sent2.error, `signIn.magicLink 2 failed: ${JSON.stringify(sent2.error)}`);
  const link2 = await fetchLastLink(email2);
  const u2 = new URL(link2.url);
  assert(u2.searchParams.get("callbackURL") === "/dashboard" && u2.searchParams.get("newUserCallbackURL") === "/welcome",
    `link params: ${link2.url}`);
  const r2 = await fetch(`${baseURL}${u2.pathname}${u2.search}`, { redirect: "manual" });
  assert(r2.status === 302 && r2.headers.get("location") === `${appOrigin}/welcome`,
    `new user redirect: ${r2.status} ${r2.headers.get("location")}`);
  assert((r2.headers.getSetCookie?.() || []).some((c) => c.includes("session_token=")), "redirect must set the session cookie");

  // the same user signing in again goes to callbackURL
  await client.signIn.magicLink({ email: email2, callbackURL: "/dashboard", newUserCallbackURL: "/welcome" });
  const link3 = await fetchLastLink(email2);
  const u3 = new URL(link3.url);
  const r3 = await fetch(`${baseURL}${u3.pathname}${u3.search}`, { redirect: "manual" });
  assert(r3.status === 302 && r3.headers.get("location") === `${appOrigin}/dashboard`,
    `existing user redirect: ${r3.status} ${r3.headers.get("location")}`);

  // 6. a cookie from a redirect authenticates a fresh client
  console.log("\n[6] session cookie from the redirect...");
  const fresh = makeClient(baseURL);
  fresh.saveCookies(r3);
  const s3 = await fresh.client.getSession();
  assert(s3.data?.user?.email === email2, `getSession after redirect: ${JSON.stringify(s3)}`);

  // 7. validation errors
  console.log("\n[7] validation errors...");
  const bad = await client.signIn.magicLink({ email: "not-an-email" });
  assert(bad.error?.status === 400 && bad.error?.code === "INVALID_EMAIL", `invalid email: ${JSON.stringify(bad.error)}`);
  const evil = await client.signIn.magicLink({ email, callbackURL: "https://evil.example.com" });
  assert(evil.error?.status === 403 && evil.error?.code === "INVALID_CALLBACK_URL", `untrusted callback: ${JSON.stringify(evil.error)}`);
  const evilVerify = await client.magicLink.verify({ query: { token: "x", callbackURL: "https://evil.example.com" } });
  assert(evilVerify.error?.status === 403 && evilVerify.error?.code === "INVALID_CALLBACK_URL",
    `untrusted verify callback: ${JSON.stringify(evilVerify.error)}`);

  console.log("\nAll magic-link client checks passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
