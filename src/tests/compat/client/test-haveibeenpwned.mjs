// Official better-auth client against goauth's have-i-been-pwned plugin (no client plugin exists; the server
// rejects compromised passwords with PASSWORD_COMPROMISED). The Go runner points the plugin at a fake range
// API whose corpus contains PWNED_PASSWORD.
import { createAuthClient } from "better-auth/client";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const pwned = process.env.PWNED_PASSWORD || "password123";

console.log("Running official better-auth/client have-i-been-pwned test against:", baseURL);

function makeClient(url) {
  const cookies = new Map();
  const client = createAuthClient({
    baseURL: url,
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
          if (str.includes("Max-Age=0")) cookies.delete(name);
          else cookies.set(name, pair.slice(i + 1).trim());
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

const MESSAGE = "The password you entered has been compromised. Please choose a different password.";

function expectCompromised(res, label) {
  assert(res.error, `${label}: expected an error, got ${JSON.stringify(res.data)}`);
  assert(res.error.status === 400 && res.error.code === "PASSWORD_COMPROMISED" && res.error.message === MESSAGE,
    `${label}: ${JSON.stringify(res.error)}`);
}

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const email = `hibp-${suffix}@example.com`;
  const safe = `Unique-${suffix}-Pass!`;
  const { client } = makeClient(baseURL);

  // 1. sign-up with a breached password
  console.log("\n[1] signUp.email with a breached password...");
  expectCompromised(await client.signUp.email({ email, password: pwned, name: "Pwned" }), "sign-up");

  // 2. sign-up with a unique password
  console.log("\n[2] signUp.email with a unique password...");
  const up = await client.signUp.email({ email, password: safe, name: "Pwned" });
  assert(!up.error && Boolean(up.data?.token), `sign-up: ${JSON.stringify(up)}`);

  // 3. change-password to a breached password, then to a unique one
  console.log("\n[3] changePassword...");
  expectCompromised(await client.changePassword({ currentPassword: safe, newPassword: pwned }), "change-password");
  const next = `${safe}-2`;
  const changed = await client.changePassword({ currentPassword: safe, newPassword: next });
  assert(!changed.error, `change-password: ${JSON.stringify(changed.error)}`);

  // 4. sign-in is never checked
  console.log("\n[4] signIn.email...");
  const { client: c2 } = makeClient(baseURL);
  const signIn = await c2.signIn.email({ email, password: next });
  assert(!signIn.error && Boolean(signIn.data?.token), `sign-in: ${JSON.stringify(signIn)}`);

  console.log("\n✅ All official better-auth/client have-i-been-pwned plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
