import { createAuthClient } from "better-auth/client";
import { emailOTPClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const rlURL = process.env.GOAUTH_RL_URL || "";

console.log("Running official better-auth/client EmailOTP test against:", baseURL);

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
    plugins: [emailOTPClient()],
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

  return { client };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

async function fetchLastOTP(url, email) {
  const res = await fetch(`${url}/test/last-otp?email=${encodeURIComponent(email)}`);
  assert(res.ok, `failed to fetch test OTP for ${email}: ${res.status}`);
  const data = await res.json();
  return data.otp;
}

async function main() {
  const ts = Date.now();
  const { client } = makeClient(baseURL);

  // 1. Test GenerateOTP + ResendStrategy="reuse" + StoreOTPEncrypted
  const signInEmail = `otp-signin-${ts}@example.com`;
  console.log("\n[1] Testing sendVerificationOtp (sign-in) + GenerateOTP + ResendStrategy=reuse...");

  const s1 = await client.emailOtp.sendVerificationOtp({ email: signInEmail, type: "sign-in" });
  assert(!s1.error, `sendVerificationOtp 1 failed: ${JSON.stringify(s1.error)}`);
  const otp1 = await fetchLastOTP(baseURL, signInEmail);
  assert(otp1 && otp1.startsWith("GO-"), `expected custom GenerateOTP prefix 'GO-', got: ${otp1}`);

  // Resending while valid must reuse the exact same OTP
  const s2 = await client.emailOtp.sendVerificationOtp({ email: signInEmail, type: "sign-in" });
  assert(!s2.error, `sendVerificationOtp 2 failed: ${JSON.stringify(s2.error)}`);
  const otp2 = await fetchLastOTP(baseURL, signInEmail);
  assert(otp1 === otp2, `expected ResendStrategy=reuse to return same OTP (${otp1} !== ${otp2})`);

  // 2. Test AllowedAttempts=3
  console.log("\n[2] Testing AllowedAttempts=3 (3 bad attempts -> 4th fails with TOO_MANY_ATTEMPTS)...");
  for (let i = 1; i <= 3; i++) {
    const bad = await client.signIn.emailOtp({ email: signInEmail, otp: "GO-0000" });
    assert(bad.error, `attempt ${i} should fail`);
    assert(bad.error.code === "INVALID_OTP", `attempt ${i} expected INVALID_OTP, got: ${JSON.stringify(bad.error)}`);
  }
  const locked = await client.signIn.emailOtp({ email: signInEmail, otp: otp2 });
  assert(locked.error, "4th attempt should fail with TOO_MANY_ATTEMPTS");
  assert(
    locked.error.code === "TOO_MANY_ATTEMPTS" || locked.error.status === 403,
    `expected TOO_MANY_ATTEMPTS (403), got: ${JSON.stringify(locked.error)}`
  );

  // 3. Re-send fresh OTP & signIn.emailOtp
  console.log("\n[3] Testing signIn.emailOtp with fresh OTP...");
  const s3 = await client.emailOtp.sendVerificationOtp({ email: signInEmail, type: "sign-in" });
  assert(!s3.error, `sendVerificationOtp 3 failed: ${JSON.stringify(s3.error)}`);
  const otp3 = await fetchLastOTP(baseURL, signInEmail);
  const signInRes = await client.signIn.emailOtp({ email: signInEmail, otp: otp3 });
  assert(!signInRes.error && signInRes.data?.user?.email === signInEmail, `signIn.emailOtp failed: ${JSON.stringify(signInRes)}`);

  // 4. Sign up password user, verify email via checkVerificationOtp + verifyEmail
  console.log("\n[4] Testing email verification (checkVerificationOtp + verifyEmail)...");
  const user2Email = `otp-verify-${ts}@example.com`;
  const { client: c2 } = makeClient(baseURL);
  const upRes = await c2.signUp.email({ email: user2Email, password: "Password123!", name: "Verify User" });
  assert(!upRes.error, `signUp failed: ${JSON.stringify(upRes.error)}`);

  const sv = await c2.emailOtp.sendVerificationOtp({ email: user2Email, type: "email-verification" });
  assert(!sv.error, `sendVerificationOtp verify failed: ${JSON.stringify(sv.error)}`);
  const verifyOTP = await fetchLastOTP(baseURL, user2Email);

  const chk = await c2.emailOtp.checkVerificationOtp({
    email: user2Email,
    otp: verifyOTP,
    type: "email-verification",
  });
  assert(!chk.error && chk.data?.success === true, `checkVerificationOtp failed: ${JSON.stringify(chk)}`);

  const ver = await c2.emailOtp.verifyEmail({ email: user2Email, otp: verifyOTP });
  assert(!ver.error && ver.data?.status === true && ver.data?.user?.emailVerified === true, `verifyEmail failed: ${JSON.stringify(ver)}`);

  // 5. Request Password Reset + Reset Password + Sign In with new password
  console.log("\n[5] Testing requestPasswordReset + resetPassword...");
  const reqReset = await c2.emailOtp.requestPasswordReset({ email: user2Email });
  assert(!reqReset.error, `requestPasswordReset failed: ${JSON.stringify(reqReset.error)}`);
  const resetOTP = await fetchLastOTP(baseURL, user2Email);

  const resetRes = await c2.emailOtp.resetPassword({
    email: user2Email,
    otp: resetOTP,
    password: "NewPassword456!",
  });
  assert(!resetRes.error, `resetPassword failed: ${JSON.stringify(resetRes.error)}`);

  const newSignIn = await c2.signIn.email({ email: user2Email, password: "NewPassword456!" });
  assert(!newSignIn.error && newSignIn.data?.user?.email === user2Email, `signIn after password reset failed: ${JSON.stringify(newSignIn)}`);

  // 6. Change Email via OTP
  console.log("\n[6] Testing requestEmailChange + changeEmail...");
  const newEmail = `otp-changed-${ts}@example.com`;
  const reqChange = await c2.emailOtp.requestEmailChange({ newEmail });
  assert(!reqChange.error, `requestEmailChange failed: ${JSON.stringify(reqChange.error)}`);
  const changeOTP = await fetchLastOTP(baseURL, newEmail);

  const chgRes = await c2.emailOtp.changeEmail({ newEmail, otp: changeOTP });
  assert(!chgRes.error, `changeEmail failed: ${JSON.stringify(chgRes.error)}`);

  const sessAfter = await c2.getSession();
  assert(!sessAfter.error && sessAfter.data?.user?.email === newEmail, `expected email changed to ${newEmail}, got: ${JSON.stringify(sessAfter.data)}`);

  // 7. Rate limit check against GOAUTH_RL_URL (Max=2)
  if (rlURL) {
    console.log("\n[7] Testing RateLimit (Max=2)...");
    const { client: rlClient } = makeClient(rlURL);
    const rlEmail = `rl-${ts}@example.com`;
    const r1 = await rlClient.emailOtp.sendVerificationOtp({ email: rlEmail, type: "sign-in" });
    assert(!r1.error, `rl 1 failed: ${JSON.stringify(r1.error)}`);
    const r2 = await rlClient.emailOtp.sendVerificationOtp({ email: rlEmail, type: "sign-in" });
    assert(!r2.error, `rl 2 failed: ${JSON.stringify(r2.error)}`);
    const r3 = await rlClient.emailOtp.sendVerificationOtp({ email: rlEmail, type: "sign-in" });
    assert(r3.error && (r3.error.status === 429 || r3.error.code === "TOO_MANY_REQUESTS"), `expected 429 rate limit on 3rd call, got: ${JSON.stringify(r3)}`);
  }

  console.log("\n✅ All official better-auth/client EmailOTP plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});

