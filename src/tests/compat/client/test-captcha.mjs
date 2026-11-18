// Official better-auth client against goauth's captcha plugin. better-auth has no captcha client plugin: the
// app passes the widget token in the x-captcha-response header through fetchOptions, as documented.
import { createAuthClient } from "better-auth/client";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";

console.log("Running official better-auth/client captcha test against:", baseURL);

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

// expectCaptchaError checks the error the client reports for better-auth's middlewareResponse
// ({message, code} with a text/plain content type).
function expectCaptchaError(res, status, code, message, label) {
  assert(res.error, `${label}: expected an error, got ${JSON.stringify(res.data)}`);
  assert(res.error.status === status, `${label}: status ${res.error.status}, want ${status}`);
  let body = res.error;
  if (typeof res.error.message === "string" && res.error.message.startsWith("{")) body = JSON.parse(res.error.message);
  assert(body.code === code && body.message === message, `${label}: error ${JSON.stringify(res.error)}`);
}

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const email = `captcha-${suffix}@example.com`;
  const password = "Password123!";
  const { client } = makeClient(baseURL);

  // 1. no token
  console.log("\n[1] signUp.email without x-captcha-response...");
  const none = await client.signUp.email({ email, password, name: "Captcha" });
  expectCaptchaError(none, 400, "MISSING_RESPONSE", "Missing CAPTCHA response", "missing token");

  // 2. a token the provider rejects
  console.log("\n[2] signUp.email with a rejected token...");
  const bad = await client.signUp.email({ email, password, name: "Captcha" }, { headers: { "x-captcha-response": "bad-token" } });
  expectCaptchaError(bad, 403, "VERIFICATION_FAILED", "Captcha verification failed", "rejected token");

  // 3. a valid token
  console.log("\n[3] signUp.email with a valid token...");
  const ok = await client.signUp.email({ email, password, name: "Captcha" }, { headers: { "x-captcha-response": "good-token" } });
  assert(!ok.error && ok.data?.user?.email === email, `signUp: ${JSON.stringify(ok)}`);
  const sess = await client.getSession();
  assert(!sess.error && sess.data?.user?.email === email, `getSession (not protected): ${JSON.stringify(sess)}`);

  // 4. sign-in is protected too
  console.log("\n[4] signIn.email...");
  const { client: c2 } = makeClient(baseURL);
  const noTok = await c2.signIn.email({ email, password });
  expectCaptchaError(noTok, 400, "MISSING_RESPONSE", "Missing CAPTCHA response", "sign-in without token");
  const signIn = await c2.signIn.email({ email, password }, { headers: { "x-captcha-response": "good-token" } });
  assert(!signIn.error && Boolean(signIn.data?.token), `signIn: ${JSON.stringify(signIn)}`);

  // 5. request-password-reset
  console.log("\n[5] requestPasswordReset...");
  const reset = await c2.requestPasswordReset({ email, redirectTo: "/reset" });
  expectCaptchaError(reset, 400, "MISSING_RESPONSE", "Missing CAPTCHA response", "request-password-reset");

  console.log("\n✅ All official better-auth/client captcha plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
