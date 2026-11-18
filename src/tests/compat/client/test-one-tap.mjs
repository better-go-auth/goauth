import { createAuthClient } from "better-auth/client";
import { oneTapClient } from "better-auth/client/plugins";

// The ID tokens are minted by the Go test with a fake Google key set (TOKEN_* env variables).
const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const disabledURL = process.env.GOAUTH_URL_DISABLED;
const env = (name) => {
  const v = process.env[name];
  if (!v) {
    console.error(`missing ${name}`);
    process.exit(1);
  }
  return v;
};

console.log("Running official better-auth/client one-tap test against:", baseURL);

// makeClient is one "browser": a client with its own cookie jar.
function makeClient(url) {
  const cookies = new Map();
  const client = createAuthClient({
    baseURL: url,
    plugins: [oneTapClient({ clientId: process.env.GOOGLE_CLIENT_ID || "client-id" })],
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", url);
        const c = Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        for (const str of ctx.response.headers.getSetCookie?.() || []) {
          const [pair] = str.split(";");
          const i = pair.indexOf("=");
          const name = pair.slice(0, i).trim();
          const value = pair.slice(i + 1).trim();
          if (str.includes("Max-Age=0") || value === "") cookies.delete(name);
          else cookies.set(name, value);
        }
      },
    },
  });
  return { client, cookies };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

function expectError(res, status, message, label) {
  assert(res.error, `${label}: expected error "${message}", got data ${JSON.stringify(res.data)}`);
  assert(res.error.status === status, `${label}: expected status ${status}, got ${JSON.stringify(res.error)}`);
  assert(res.error.message === message, `${label}: expected message "${message}", got ${JSON.stringify(res.error)}`);
}

// callback is what oneTapClient's oneTap() does with Google's credential once the browser prompt
// returns it: $fetch("/one-tap/callback", { method: "POST", body: { idToken } }).
function callback(client, idToken) {
  return client.$fetch("/one-tap/callback", { method: "POST", body: { idToken } });
}

async function main() {
  // 1. oneTap() needs a browser (Google Identity Services); in Node it warns and returns undefined
  console.log("\n[1] oneTap() outside a browser...");
  const { client: probe } = makeClient(baseURL);
  assert(typeof probe.oneTap === "function", "oneTapClient should add oneTap()");
  const headless = await probe.oneTap();
  assert(headless === undefined, `oneTap() in Node should return undefined, got ${JSON.stringify(headless)}`);

  // 2. a new Google account signs up and gets a session cookie
  console.log("\n[2] sign-up through the callback...");
  const { client, cookies } = makeClient(baseURL);
  const first = await callback(client, env("TOKEN_NEW"));
  assert(!first.error, `callback failed: ${JSON.stringify(first.error)}`);
  assert(typeof first.data?.token === "string" && first.data.token.length > 0, `no token: ${JSON.stringify(first.data)}`);
  assert(first.data.user?.email === "onetap.user@example.com", `email should be lower-cased: ${JSON.stringify(first.data.user)}`);
  assert(first.data.user?.emailVerified === true && first.data.user?.name === "One Tap", `user: ${JSON.stringify(first.data.user)}`);
  assert(Object.keys(first.data).sort().join(",") === "token,user", `keys: ${Object.keys(first.data)}`);
  assert(cookies.has("better-auth.session_token"), "callback should set the session cookie");
  const session = await client.getSession();
  assert(session.data?.user?.id === first.data.user.id, `getSession: ${JSON.stringify(session.data)}`);

  // 3. the same Google account signs in again on another browser: same user
  console.log("\n[3] sign-in again...");
  const { client: second } = makeClient(baseURL);
  const again = await callback(second, env("TOKEN_SAME"));
  assert(!again.error && again.data?.user?.id === first.data.user.id, `second sign-in: ${JSON.stringify(again)}`);
  assert(again.data.token !== first.data.token, "a new session is created");

  // 4. invalid tokens
  console.log("\n[4] invalid tokens...");
  expectError(await callback(probe, env("TOKEN_WRONG_AUDIENCE")), 400, "invalid id token", "wrong audience");
  expectError(await callback(probe, env("TOKEN_BAD_SIGNATURE")), 400, "invalid id token", "bad signature");
  expectError(await callback(probe, "garbage"), 400, "invalid id token", "garbage");
  const missing = await probe.$fetch("/one-tap/callback", { method: "POST", body: {} });
  assert(missing.error?.status === 400, `missing idToken should be 400: ${JSON.stringify(missing)}`);

  // 5. no email in the token: 200 { error }
  console.log("\n[5] token without email...");
  const noEmail = await callback(probe, env("TOKEN_NO_EMAIL"));
  assert(!noEmail.error && noEmail.data?.error === "Email not available in token", `no email: ${JSON.stringify(noEmail)}`);

  // 6. an existing user whose email is not verified is not linked implicitly
  console.log("\n[6] existing unverified user...");
  const { client: local } = makeClient(baseURL);
  const signUp = await local.signUp.email({ email: "onetap.link@example.com", password: "OneTapPass123!", name: "Link" });
  assert(!signUp.error, `sign-up failed: ${JSON.stringify(signUp.error)}`);
  expectError(await callback(probe, env("TOKEN_LINK")), 401, "account not linked", "link unverified local user");

  // 7. sign-out works with the fedcm fetch plugin outside a browser
  console.log("\n[7] sign-out...");
  const out = await client.signOut();
  assert(!out.error && out.data?.success === true, `sign-out: ${JSON.stringify(out)}`);

  // 8. disableSignup refuses unknown Google accounts
  if (disabledURL) {
    console.log("\n[8] disableSignup...");
    const { client: d } = makeClient(disabledURL);
    expectError(await callback(d, env("TOKEN_NEW")), 401, "signup disabled", "disableSignup");
  }

  console.log("\nAll one-tap client checks passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
