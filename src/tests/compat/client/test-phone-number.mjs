import { createAuthClient } from "better-auth/client";
import { phoneNumberClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";

console.log("Running official better-auth/client phone-number test against:", baseURL);

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
    plugins: [phoneNumberClient()],
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

  return { client, cookies };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

async function lastSMS(phone, type = "otp") {
  const res = await fetch(`${baseURL}/test/last-sms?phone=${encodeURIComponent(phone)}&type=${type}`);
  assert(res.ok, `failed to fetch test SMS (${type}) for ${phone}: ${res.status}`);
  const data = await res.json();
  return data.code;
}

function expectError(res, code, status, label) {
  assert(res.error, `${label}: expected error ${code}, got data ${JSON.stringify(res.data)}`);
  assert(res.error.code === code, `${label}: expected code ${code}, got ${JSON.stringify(res.error)}`);
  if (status) assert(res.error.status === status, `${label}: expected status ${status}, got ${res.error.status}`);
}

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const phoneA = `+1555${suffix}`;
  const phoneB = `+1666${suffix}`;
  const phoneC = `+1777${suffix}`;
  const { client } = makeClient(baseURL);

  // 1. sendOtp + wrong code + sign-up on verification
  console.log("\n[1] sendOtp + verify (signUpOnVerification)...");
  const sent = await client.phoneNumber.sendOtp({ phoneNumber: phoneA });
  assert(!sent.error && sent.data?.message === "code sent", `sendOtp failed: ${JSON.stringify(sent)}`);
  const codeA = await lastSMS(phoneA);
  assert(/^\d{6}$/.test(codeA), `expected 6 digit code, got ${codeA}`);

  const wrong = await client.phoneNumber.verify({ phoneNumber: phoneA, code: codeA === "000000" ? "111111" : "000000" });
  expectError(wrong, "INVALID_OTP", 400, "verify wrong code");

  const ver = await client.phoneNumber.verify({ phoneNumber: phoneA, code: codeA });
  assert(
    !ver.error &&
      ver.data?.status === true &&
      Boolean(ver.data?.token) &&
      ver.data?.user?.phoneNumber === phoneA &&
      ver.data?.user?.phoneNumberVerified === true &&
      ver.data?.user?.emailVerified === false,
    `verify failed: ${JSON.stringify(ver)}`
  );
  const userID = ver.data.user.id;

  // 2. getSession reflects the phone-number user
  console.log("\n[2] getSession after verification...");
  const sess = await client.getSession();
  assert(!sess.error && sess.data?.user?.id === userID && sess.data?.user?.phoneNumber === phoneA, `getSession failed: ${JSON.stringify(sess)}`);

  // 3. phone-only users have no password yet
  console.log("\n[3] signIn.phoneNumber without a password...");
  const { client: c2 } = makeClient(baseURL);
  const noPass = await c2.signIn.phoneNumber({ phoneNumber: phoneA, password: "PhonePass123!" });
  expectError(noPass, "INVALID_PHONE_NUMBER_OR_PASSWORD", 401, "signIn before reset");

  // 4. password reset by SMS creates the credential account
  console.log("\n[4] requestPasswordReset + resetPassword...");
  const req = await c2.phoneNumber.requestPasswordReset({ phoneNumber: phoneA });
  assert(!req.error && req.data?.status === true, `requestPasswordReset failed: ${JSON.stringify(req)}`);
  const resetCode = await lastSMS(phoneA, "reset");
  const badReset = await c2.phoneNumber.resetPassword({ phoneNumber: phoneA, otp: "nope", newPassword: "PhonePass123!" });
  expectError(badReset, "INVALID_OTP", 400, "resetPassword wrong otp");
  const shortPw = await c2.phoneNumber.resetPassword({ phoneNumber: phoneA, otp: resetCode, newPassword: "short" });
  expectError(shortPw, "PASSWORD_TOO_SHORT", 400, "resetPassword short password");
  const reset = await c2.phoneNumber.resetPassword({ phoneNumber: phoneA, otp: resetCode, newPassword: "PhonePass123!" });
  assert(!reset.error && reset.data?.status === true, `resetPassword failed: ${JSON.stringify(reset)}`);

  // 5. signIn.phoneNumber with the new password
  console.log("\n[5] signIn.phoneNumber...");
  const badSignIn = await c2.signIn.phoneNumber({ phoneNumber: phoneA, password: "wrong-password" });
  expectError(badSignIn, "INVALID_PHONE_NUMBER_OR_PASSWORD", 401, "signIn wrong password");
  const signIn = await c2.signIn.phoneNumber({ phoneNumber: phoneA, password: "PhonePass123!", rememberMe: true });
  assert(
    !signIn.error && Boolean(signIn.data?.token) && signIn.data?.user?.id === userID && signIn.data?.user?.phoneNumber === phoneA,
    `signIn.phoneNumber failed: ${JSON.stringify(signIn)}`
  );
  const sess2 = await c2.getSession();
  assert(!sess2.error && sess2.data?.user?.id === userID, `getSession after signIn failed: ${JSON.stringify(sess2)}`);

  // 6. updatePhoneNumber moves the signed-in user to a new verified number
  console.log("\n[6] verify with updatePhoneNumber...");
  const sentB = await c2.phoneNumber.sendOtp({ phoneNumber: phoneB });
  assert(!sentB.error, `sendOtp B failed: ${JSON.stringify(sentB)}`);
  const upd = await c2.phoneNumber.verify({ phoneNumber: phoneB, code: await lastSMS(phoneB), updatePhoneNumber: true });
  assert(
    !upd.error && upd.data?.status === true && upd.data?.user?.id === userID && upd.data?.user?.phoneNumber === phoneB && upd.data?.user?.phoneNumberVerified === true,
    `updatePhoneNumber failed: ${JSON.stringify(upd)}`
  );
  const sess3 = await c2.getSession();
  assert(!sess3.error && sess3.data?.user?.phoneNumber === phoneB, `getSession after update failed: ${JSON.stringify(sess3)}`);
  const oldNumber = await makeClient(baseURL).client.signIn.phoneNumber({ phoneNumber: phoneA, password: "PhonePass123!" });
  expectError(oldNumber, "INVALID_PHONE_NUMBER_OR_PASSWORD", 401, "signIn with the old number");

  // 7. another user cannot take an existing number
  console.log("\n[7] updatePhoneNumber conflict...");
  const { client: c3 } = makeClient(baseURL);
  const up = await c3.signUp.email({ email: `phone-${suffix}@example.com`, password: "Password123!", name: "Other" });
  assert(!up.error, `signUp failed: ${JSON.stringify(up.error)}`);
  await c3.phoneNumber.sendOtp({ phoneNumber: phoneB });
  const conflict = await c3.phoneNumber.verify({ phoneNumber: phoneB, code: await lastSMS(phoneB), updatePhoneNumber: true });
  expectError(conflict, "PHONE_NUMBER_EXIST", 400, "updatePhoneNumber conflict");

  // 8. lockout after allowed attempts
  console.log("\n[8] TOO_MANY_ATTEMPTS...");
  await client.phoneNumber.sendOtp({ phoneNumber: phoneC });
  const codeC = await lastSMS(phoneC);
  for (let i = 1; i <= 3; i++) {
    const bad = await client.phoneNumber.verify({ phoneNumber: phoneC, code: "x" });
    expectError(bad, "INVALID_OTP", 400, `attempt ${i}`);
  }
  const locked = await client.phoneNumber.verify({ phoneNumber: phoneC, code: codeC });
  expectError(locked, "TOO_MANY_ATTEMPTS", 403, "locked out");
  const gone = await client.phoneNumber.verify({ phoneNumber: phoneC, code: codeC });
  expectError(gone, "OTP_NOT_FOUND", 400, "after lockout");

  // 9. disableSession returns no token
  console.log("\n[9] verify with disableSession...");
  await client.phoneNumber.sendOtp({ phoneNumber: phoneC });
  const noSess = await client.phoneNumber.verify({ phoneNumber: phoneC, code: await lastSMS(phoneC), disableSession: true });
  assert(!noSess.error && noSess.data?.status === true && noSess.data?.token === null && noSess.data?.user?.phoneNumber === phoneC, `disableSession failed: ${JSON.stringify(noSess)}`);

  // 10. phoneNumberValidator
  console.log("\n[10] phoneNumberValidator...");
  const invalid = await client.phoneNumber.sendOtp({ phoneNumber: "12345" });
  expectError(invalid, "INVALID_PHONE_NUMBER", 400, "invalid phone");

  console.log("\n✅ All official better-auth/client phone-number plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
