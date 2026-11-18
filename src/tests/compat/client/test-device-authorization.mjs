import { createAuthClient } from "better-auth/client";
import { deviceAuthorizationClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
// the Go runner configures a 1 s polling interval and a "cli" / "tv" client allow-list
const intervalMs = 1000;

console.log("Running official better-auth/client device-authorization test against:", baseURL);

// makeBrowser is the user's browser: a cookie jar, like a real one.
function makeBrowser(url) {
  const cookies = new Map();
  const cookieHeader = () => Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
  function saveCookies(response) {
    for (const str of response.headers.getSetCookie?.() || []) {
      const [pair] = str.split(";");
      const idx = pair.indexOf("=");
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      if (str.includes("Max-Age=0") || value === "") cookies.delete(name);
      else cookies.set(name, value);
    }
  }
  return createAuthClient({
    baseURL: url,
    plugins: [deviceAuthorizationClient()],
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", url);
        const c = cookieHeader();
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        saveCookies(ctx.response);
      },
    },
  });
}

// makeDevice is the CLI / TV: no cookies, no origin.
function makeDevice(url) {
  return createAuthClient({ baseURL: url, plugins: [deviceAuthorizationClient()] });
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

function expectOAuthError(res, error, status, label) {
  assert(res.error, `${label}: expected error ${error}, got data ${JSON.stringify(res.data)}`);
  assert(res.error.error === error, `${label}: expected error ${error}, got ${JSON.stringify(res.error)}`);
  assert(typeof res.error.error_description === "string", `${label}: missing error_description: ${JSON.stringify(res.error)}`);
  if (status) assert(res.error.status === status, `${label}: expected status ${status}, got ${res.error.status}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// pollToken polls device.token like an RFC 8628 client: it waits `interval` and backs off on slow_down.
async function pollToken(device, deviceCode, clientId, maxPolls = 10) {
  let wait = intervalMs;
  for (let i = 0; i < maxPolls; i++) {
    await sleep(wait);
    const res = await device.device.token({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: deviceCode,
      client_id: clientId,
    });
    if (!res.error) return res;
    if (res.error.error === "authorization_pending") continue;
    if (res.error.error === "slow_down") {
      wait += intervalMs;
      continue;
    }
    return res;
  }
  throw new Error("polling did not finish");
}

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const device = makeDevice(baseURL);
  const browser = makeBrowser(baseURL);

  // 1. device.code returns the RFC 8628 response
  console.log("\n[1] device.code...");
  const code = await device.device.code({ client_id: "cli", scope: "openid profile" });
  assert(!code.error, `device.code failed: ${JSON.stringify(code.error)}`);
  const d = code.data;
  assert(typeof d.device_code === "string" && d.device_code.length === 40, `device_code: ${JSON.stringify(d)}`);
  assert(/^[A-Z2-9]{8}$/.test(d.user_code), `user_code: ${d.user_code}`);
  assert(d.verification_uri.endsWith("/device"), `verification_uri: ${d.verification_uri}`);
  assert(d.verification_uri_complete === `${d.verification_uri}?user_code=${d.user_code}`, `verification_uri_complete: ${d.verification_uri_complete}`);
  assert(d.interval === 1 && d.expires_in === 1800, `interval/expires_in: ${JSON.stringify(d)}`);

  // 2. unknown client
  console.log("\n[2] device.code with an unknown client...");
  expectOAuthError(await device.device.code({ client_id: "evil" }), "invalid_client", 400, "invalid client");

  // 3. polling before approval: pending, then slow_down when polling too fast
  console.log("\n[3] device.token pending / slow_down...");
  const tokenBody = { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: d.device_code, client_id: "cli" };
  expectOAuthError(await device.device.token(tokenBody), "authorization_pending", 400, "pending");
  expectOAuthError(await device.device.token(tokenBody), "slow_down", 400, "slow_down");
  expectOAuthError(await device.device.token({ ...tokenBody, client_id: "tv" }), "invalid_grant", 400, "client mismatch");

  // 4. the user signs in, opens the verification page and approves
  console.log("\n[4] sign up, device verify, device.approve...");
  const unauth = await browser.device.approve({ userCode: d.user_code });
  expectOAuthError(unauth, "unauthorized", 401, "approve without session");
  const up = await browser.signUp.email({ email: `device-${suffix}@example.com`, password: "Password123!", name: "Device User" });
  assert(!up.error, `signUp failed: ${JSON.stringify(up.error)}`);
  const notClaimed = await browser.device.approve({ userCode: d.user_code });
  expectOAuthError(notClaimed, "invalid_request", 400, "approve before verify");
  const verify = await browser.device({ query: { user_code: d.user_code } });
  assert(!verify.error && verify.data.status === "pending" && verify.data.user_code === d.user_code, `device verify: ${JSON.stringify(verify)}`);
  const bad = await browser.device({ query: { user_code: "NOPE1234" } });
  expectOAuthError(bad, "invalid_request", 400, "unknown user code");
  const approve = await browser.device.approve({ userCode: d.user_code });
  assert(!approve.error && approve.data.success === true, `approve: ${JSON.stringify(approve)}`);
  const verified = await browser.device({ query: { user_code: d.user_code } });
  assert(!verified.error && verified.data.status === "approved", `device verify after approve: ${JSON.stringify(verified)}`);

  // 5. the device polls and receives a session token
  console.log("\n[5] device.token polling...");
  const tok = await pollToken(device, d.device_code, "cli");
  assert(!tok.error, `token failed: ${JSON.stringify(tok.error)}`);
  assert(typeof tok.data.access_token === "string" && tok.data.token_type === "Bearer" && tok.data.scope === "openid profile" && tok.data.expires_in > 0,
    `token: ${JSON.stringify(tok.data)}`);

  // 6. the token is a session: getSession with it as bearer token
  console.log("\n[6] getSession with the access token...");
  const sess = await device.getSession({ fetchOptions: { headers: { Authorization: `Bearer ${tok.data.access_token}` } } });
  assert(!sess.error && sess.data?.user?.id === up.data.user.id && sess.data?.session?.token === tok.data.access_token,
    `getSession with bearer: ${JSON.stringify(sess)}`);

  // 7. the device code cannot be used again
  console.log("\n[7] device code reuse...");
  await sleep(intervalMs);
  expectOAuthError(await device.device.token(tokenBody), "invalid_grant", 400, "reuse");

  // 8. the deny path
  console.log("\n[8] device.deny...");
  const code2 = await device.device.code({ client_id: "tv" });
  assert(!code2.error, `device.code (tv): ${JSON.stringify(code2.error)}`);
  const v2 = await browser.device({ query: { user_code: code2.data.user_code } });
  assert(!v2.error, `device verify (tv): ${JSON.stringify(v2.error)}`);
  const deny = await browser.device.deny({ userCode: code2.data.user_code });
  assert(!deny.error && deny.data.success === true, `deny: ${JSON.stringify(deny)}`);
  const denied = await pollToken(device, code2.data.device_code, "tv");
  expectOAuthError(denied, "access_denied", 400, "denied");
  const again = await browser.device.approve({ userCode: code2.data.user_code });
  expectOAuthError(again, "invalid_request", 400, "approve after deny");

  console.log("\n✅ All official better-auth/client device-authorization plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
