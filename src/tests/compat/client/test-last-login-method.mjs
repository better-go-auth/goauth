// Official better-auth client (lastLoginMethodClient) against goauth's last-login-method plugin.
// lastLoginMethodClient reads document.cookie, which does not exist in Node: its actions return null / false
// here, so the script checks the cookie the server sets through the client's own response hooks.
import { createAuthClient } from "better-auth/client";
import { lastLoginMethodClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const COOKIE = "better-auth.last_used_login_method";

console.log("Running official better-auth/client last-login-method test against:", baseURL);

function makeClient(url) {
  const cookies = new Map();
  const setCookies = [];
  const client = createAuthClient({
    baseURL: url,
    plugins: [lastLoginMethodClient()],
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", url);
        const c = Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        setCookies.length = 0;
        for (const str of ctx.response.headers.getSetCookie?.() || []) {
          setCookies.push(str);
          const [pair] = str.split(";");
          const i = pair.indexOf("=");
          const name = pair.slice(0, i).trim();
          if (str.includes("Max-Age=0")) cookies.delete(name);
          else cookies.set(name, pair.slice(i + 1).trim());
        }
      },
    },
  });
  return { client, cookies, setCookies };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

// lastSetCookie returns the raw Set-Cookie of the last-login-method cookie in the last response.
function lastSetCookie(setCookies) {
  return setCookies.find((s) => s.startsWith(`${COOKIE}=`));
}

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const email = `last-${suffix}@example.com`;
  const password = "Password123!";
  const { client, cookies, setCookies } = makeClient(baseURL);

  // 1. the client plugin's actions exist (and read document.cookie, absent in Node)
  console.log("\n[1] client actions...");
  assert(typeof client.getLastUsedLoginMethod === "function", "getLastUsedLoginMethod missing");
  assert(client.getLastUsedLoginMethod() === null, "no document: null");
  assert(client.isLastUsedLoginMethod("email") === false, "no document: false");
  client.clearLastUsedLoginMethod();

  // 2. sign-up sets the cookie: "email", not HttpOnly, 30 days
  console.log("\n[2] signUp.email...");
  const up = await client.signUp.email({ email, password, name: "Last" });
  assert(!up.error, `signUp: ${JSON.stringify(up.error)}`);
  const raw = lastSetCookie(setCookies);
  assert(raw && raw.startsWith(`${COOKIE}=email;`), `sign-up Set-Cookie: ${JSON.stringify(setCookies)}`);
  assert(!/HttpOnly/i.test(raw) && /Max-Age=2592000/.test(raw) && /Path=\//.test(raw) && /SameSite=Lax/i.test(raw), `attributes: ${raw}`);
  assert(cookies.get(COOKIE) === "email", "cookie stored");

  // 3. getSession does not touch it; a failed sign-in neither
  console.log("\n[3] getSession / failed signIn...");
  await client.getSession();
  assert(!lastSetCookie(setCookies), `getSession set it: ${JSON.stringify(setCookies)}`);
  const { client: c2, setCookies: sc2 } = makeClient(baseURL);
  const bad = await c2.signIn.email({ email, password: "wrong-password" });
  assert(bad.error?.status === 401 && !lastSetCookie(sc2), `failed sign-in: ${JSON.stringify(sc2)}`);

  // 4. a successful sign-in sets it again
  console.log("\n[4] signIn.email...");
  const ok = await c2.signIn.email({ email, password });
  assert(!ok.error && lastSetCookie(sc2)?.startsWith(`${COOKIE}=email;`), `sign-in: ${JSON.stringify(sc2)}`);

  console.log("\n✅ All official better-auth/client last-login-method plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
