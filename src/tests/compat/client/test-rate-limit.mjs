import { createAuthClient } from "better-auth/client";

// Official better-auth client against goauth's global rate limiter (AuthConfig.RateLimit enabled, plus a
// custom rule of 2 requests per minute on /get-session).
const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";

console.log("Running official better-auth/client rate-limit test against:", baseURL);

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

// every client sends its own X-Forwarded-For, so each scenario has its own counters
function makeClient(ip) {
  const seen = { retryAfter: null, contentType: null, status: null };
  const client = createAuthClient({
    baseURL,
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", baseURL);
        ctx.headers.set("x-forwarded-for", ip);
      },
      onError(ctx) {
        seen.status = ctx.response.status;
        seen.retryAfter = ctx.response.headers.get("x-retry-after");
        seen.contentType = ctx.response.headers.get("content-type");
      },
    },
  });
  return { client, seen };
}

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const email = `rl-${suffix}@example.com`;
  const password = "Password123!";

  // 1. sign-up is limited separately (3 per 10 s); one request is fine
  console.log("\n[1] signUp.email...");
  const { client: setup } = makeClient("198.51.100.1");
  const up = await setup.signUp.email({ email, password, name: "Rate Limit User" });
  assert(!up.error && up.data?.token, `signUp: ${JSON.stringify(up)}`);

  // 2. /sign-in/*: 3 requests per 10 s, failed ones count too
  console.log("\n[2] signIn.email x3 (wrong password) then a 4th...");
  const { client, seen } = makeClient("198.51.100.2");
  for (let i = 0; i < 3; i++) {
    const res = await client.signIn.email({ email, password: "wrong-password" });
    assert(res.error?.status === 401 && res.error?.code === "INVALID_EMAIL_OR_PASSWORD", `sign-in ${i + 1}: ${JSON.stringify(res)}`);
  }
  const limited = await client.signIn.email({ email, password });
  assert(limited.data === null && limited.error, `4th sign-in should fail: ${JSON.stringify(limited)}`);
  assert(limited.error.status === 429, `status: ${JSON.stringify(limited.error)}`);
  assert(limited.error.statusText === "Too Many Requests", `statusText: ${JSON.stringify(limited.error)}`);
  assert(limited.error.message === "Too many requests. Please try again later.", `message: ${JSON.stringify(limited.error)}`);
  const retry = Number(seen.retryAfter);
  assert(seen.status === 429 && Number.isInteger(retry) && retry >= 1 && retry <= 10, `X-Retry-After: ${JSON.stringify(seen)}`);
  assert(seen.contentType === "text/plain;charset=UTF-8", `content-type: ${seen.contentType}`);

  // 3. the same client with throw: true gets a BetterFetchError with status 429
  console.log("\n[3] throw: true...");
  let thrown = null;
  try {
    await client.signIn.email({ email, password }, { throw: true });
  } catch (e) {
    thrown = e;
  }
  assert(thrown && thrown.status === 429 && thrown.error?.message === "Too many requests. Please try again later.",
    `thrown: ${JSON.stringify(thrown)}`);

  // 4. another IP is not affected and signs in
  console.log("\n[4] other IP...");
  const { client: other } = makeClient("198.51.100.3");
  const ok = await other.signIn.email({ email, password });
  assert(!ok.error && ok.data?.token, `other IP sign-in: ${JSON.stringify(ok)}`);

  // 5. custom rule on /get-session: 2 per minute
  console.log("\n[5] getSession custom rule...");
  const { client: sess, seen: sessSeen } = makeClient("198.51.100.4");
  for (let i = 0; i < 2; i++) {
    const r = await sess.getSession();
    assert(!r.error, `getSession ${i + 1}: ${JSON.stringify(r)}`);
  }
  const r3 = await sess.getSession();
  assert(r3.error?.status === 429, `3rd getSession: ${JSON.stringify(r3)}`);
  assert(Number(sessSeen.retryAfter) > 10 && Number(sessSeen.retryAfter) <= 60, `custom rule retry: ${sessSeen.retryAfter}`);

  console.log("\nAll rate-limit client checks passed.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
