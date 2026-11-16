// Official better-auth client test for the goauth two-factor plugin.
// Run by src/tests/compat/twofactorclient/client_test.go (GOAUTH_URL points at the in-process server).
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { createOTP } from "@better-auth/utils/otp";
import { base32 } from "@better-auth/utils/base32";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const issuer = process.env.GOAUTH_ISSUER || "GoAuth Client";

console.log("Running official better-auth/client two-factor test against:", baseURL);

// makeClient returns a client with its own cookie jar (one "browser").
function makeClient() {
  const cookies = new Map();
  const redirects = [];

  function getCookieHeader() {
    return Array.from(cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }

  function saveCookies(response) {
    const setCookies = response.headers.getSetCookie?.() || [];
    if (setCookies.length === 0) {
      const raw = response.headers.get("set-cookie");
      if (raw) setCookies.push(raw);
    }
    for (const str of setCookies) {
      const parts = str.split(";")[0].split("=");
      const name = parts[0]?.trim();
      const value = parts.slice(1).join("=").trim();
      if (!name) continue;
      if (/max-age=0/i.test(str) || /max-age=-/i.test(str) || value === "") cookies.delete(name);
      else cookies.set(name, value);
    }
  }

  const client = createAuthClient({
    baseURL,
    plugins: [
      twoFactorClient({
        onTwoFactorRedirect: async (ctx) => {
          redirects.push(ctx.twoFactorMethods);
        },
      }),
    ],
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", baseURL);
        const c = getCookieHeader();
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        saveCookies(ctx.response);
      },
    },
  });

  return { client, cookies, redirects };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

async function fetchLastOTP(email) {
  const res = await fetch(`${baseURL}/test/last-otp?email=${encodeURIComponent(email)}`);
  assert(res.ok, `failed to fetch test OTP for ${email}: ${res.status}`);
  return (await res.json()).otp;
}

function secretFromURI(uri) {
  const u = new URL(uri);
  return new TextDecoder().decode(base32.decode(u.searchParams.get("secret")));
}

async function totpCode(secret) {
  return createOTP(secret, { digits: 6, period: 30 }).totp();
}

async function main() {
  const email = `two-factor-${Date.now()}@example.com`;
  const password = "Password123!";
  const a = makeClient();

  // 1. sign up and enable
  console.log("\n[1] signUp + twoFactor.enable");
  const up = await a.client.signUp.email({ email, password, name: "Two Factor" });
  assert(!up.error, `signUp failed: ${JSON.stringify(up.error)}`);

  const badEnable = await a.client.twoFactor.enable({ password: "wrong-password" });
  assert(badEnable.error?.code === "INVALID_PASSWORD", `enable with wrong password: ${JSON.stringify(badEnable)}`);

  const en = await a.client.twoFactor.enable({ password });
  assert(!en.error, `enable failed: ${JSON.stringify(en.error)}`);
  assert(en.data.backupCodes?.length === 10, `expected 10 backup codes: ${JSON.stringify(en.data)}`);
  const secret = secretFromURI(en.data.totpURI);
  const expectedURI = createOTP(secret, { digits: 6, period: 30 }).url(issuer, email);
  assert(en.data.totpURI === expectedURI, `totpURI mismatch:\n ${en.data.totpURI}\n ${expectedURI}`);
  const backupCodes = en.data.backupCodes;

  // 2. confirm the TOTP setup
  console.log("\n[2] twoFactor.verifyTotp enables 2FA");
  const bad = await a.client.twoFactor.verifyTotp({ code: "000000" });
  assert(bad.error?.code === "INVALID_CODE" && bad.error.status === 401, `bad code: ${JSON.stringify(bad.error)}`);
  const vt = await a.client.twoFactor.verifyTotp({ code: await totpCode(secret) });
  assert(!vt.error, `verifyTotp failed: ${JSON.stringify(vt.error)}`);
  let s = await a.client.getSession();
  assert(s.data?.user?.twoFactorEnabled === true, `session should have twoFactorEnabled: ${JSON.stringify(s.data)}`);

  const uri = await a.client.twoFactor.getTotpUri({ password });
  assert(!uri.error && secretFromURI(uri.data.totpURI) === secret, `getTotpUri: ${JSON.stringify(uri)}`);

  // 3. sign in → challenge
  console.log("\n[3] signIn.email returns twoFactorRedirect");
  await a.client.signOut();
  const si = await a.client.signIn.email({ email, password });
  assert(!si.error && si.data?.twoFactorRedirect === true, `expected twoFactorRedirect: ${JSON.stringify(si)}`);
  assert(
    JSON.stringify(si.data.twoFactorMethods) === JSON.stringify(["totp", "otp"]),
    `methods: ${JSON.stringify(si.data.twoFactorMethods)}`
  );
  assert(a.redirects.length === 1, `onTwoFactorRedirect should be called once, got ${a.redirects.length}`);
  s = await a.client.getSession();
  assert(!s.data, `no session before 2FA: ${JSON.stringify(s.data)}`);
  assert(a.cookies.has("better-auth.two_factor"), "two_factor cookie missing");

  // 4. verify TOTP and trust the device
  console.log("\n[4] verifyTotp with trustDevice");
  const ok = await a.client.twoFactor.verifyTotp({ code: await totpCode(secret), trustDevice: true });
  assert(!ok.error && ok.data?.token && ok.data.user?.email === email, `verifyTotp sign-in: ${JSON.stringify(ok)}`);
  assert(a.cookies.has("better-auth.trust_device"), "trust_device cookie missing");
  assert(!a.cookies.has("better-auth.two_factor"), "two_factor cookie should be cleared");
  s = await a.client.getSession();
  assert(s.data?.user?.email === email, `session after 2FA: ${JSON.stringify(s.data)}`);

  // 5. trusted device skips 2FA
  console.log("\n[5] trusted device skips the challenge");
  const trustBefore = a.cookies.get("better-auth.trust_device");
  await a.client.signOut();
  const si2 = await a.client.signIn.email({ email, password });
  assert(!si2.error && si2.data?.token && !si2.data.twoFactorRedirect, `trusted sign-in: ${JSON.stringify(si2)}`);
  assert(a.cookies.get("better-auth.trust_device") !== trustBefore, "trust_device should rotate");
  assert(a.redirects.length === 1, "onTwoFactorRedirect must not fire for a trusted device");

  // 6. OTP on another device
  console.log("\n[6] OTP flow on a new device");
  const b = makeClient();
  const si3 = await b.client.signIn.email({ email, password });
  assert(si3.data?.twoFactorRedirect === true, `device b challenge: ${JSON.stringify(si3)}`);
  const send = await b.client.twoFactor.sendOtp();
  assert(!send.error && send.data?.status === true, `sendOtp: ${JSON.stringify(send)}`);
  const otp = await fetchLastOTP(email);
  const badOtp = await b.client.twoFactor.verifyOtp({ code: "999999x" });
  assert(badOtp.error?.code === "INVALID_CODE", `bad otp: ${JSON.stringify(badOtp.error)}`);
  const vo = await b.client.twoFactor.verifyOtp({ code: otp });
  assert(!vo.error && vo.data?.token, `verifyOtp: ${JSON.stringify(vo)}`);
  s = await b.client.getSession();
  assert(s.data?.user?.email === email, "device b should have a session");

  // 7. backup codes
  console.log("\n[7] backup code sign-in, single use");
  const c = makeClient();
  await c.client.signIn.email({ email, password });
  const vb = await c.client.twoFactor.verifyBackupCode({ code: backupCodes[0] });
  assert(!vb.error && vb.data?.token, `verifyBackupCode: ${JSON.stringify(vb)}`);
  const d = makeClient();
  await d.client.signIn.email({ email, password });
  const reuse = await d.client.twoFactor.verifyBackupCode({ code: backupCodes[0] });
  assert(reuse.error?.code === "INVALID_BACKUP_CODE", `reused backup code: ${JSON.stringify(reuse)}`);

  const gen = await c.client.twoFactor.generateBackupCodes({ password });
  assert(!gen.error && gen.data?.status === true && gen.data.backupCodes.length === 10, `generateBackupCodes: ${JSON.stringify(gen)}`);
  const vb2 = await d.client.twoFactor.verifyBackupCode({ code: gen.data.backupCodes[0] });
  assert(!vb2.error && vb2.data?.token, `new backup code: ${JSON.stringify(vb2)}`);

  // 8. disable
  console.log("\n[8] twoFactor.disable");
  const dis = await c.client.twoFactor.disable({ password });
  assert(!dis.error && dis.data?.status === true, `disable: ${JSON.stringify(dis)}`);
  s = await c.client.getSession();
  // goauth's user DTO omits twoFactorEnabled when false (better-auth sends false)
  assert(s.data?.user && !s.data.user.twoFactorEnabled, `twoFactorEnabled should be false: ${JSON.stringify(s.data)}`);
  const e = makeClient();
  const si4 = await e.client.signIn.email({ email, password });
  assert(!si4.error && si4.data?.token && !si4.data.twoFactorRedirect, `sign-in after disable: ${JSON.stringify(si4)}`);

  console.log("\nAll two-factor client checks passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
