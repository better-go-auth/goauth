import { createHash } from "node:crypto";
import { createAuthClient } from "better-auth/client";
import { oneTimeTokenClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const hashedURL = process.env.GOAUTH_URL_HASHED;
const disabledURL = process.env.GOAUTH_URL_DISABLED;

console.log("Running official better-auth/client one-time-token test against:", baseURL);

// makeClient is one "device": a client with its own cookie jar.
function makeClient(url) {
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
        if (str.includes("Max-Age=0") || value === "") cookies.delete(name);
        else cookies.set(name, value);
      }
    }
  }

  const client = createAuthClient({
    baseURL: url,
    plugins: [oneTimeTokenClient()],
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", url);
        const c = getCookieHeader();
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        saveCookies(ctx.response);
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

async function signUp(client, email) {
  const res = await client.signUp.email({ email, password: "OttPass123!", name: email.split("@")[0] });
  assert(!res.error && res.data?.token, `signUp ${email} failed: ${JSON.stringify(res)}`);
  return res.data;
}

async function testJSON(url, path) {
  const res = await fetch(`${url}${path}`);
  assert(res.ok, `test endpoint ${path} failed: ${res.status}`);
  return res.json();
}

function defaultKeyHasher(token) {
  return createHash("sha256").update(token).digest("base64url");
}

async function main() {
  const suffix = String(Date.now()).slice(-7);

  // 1. generate requires a session
  console.log("\n[1] generate without a session...");
  const { client: anon } = makeClient(baseURL);
  const noSession = await anon.oneTimeToken.generate();
  assert(noSession.error?.status === 401, `generate without session should be 401, got ${JSON.stringify(noSession)}`);

  // 2. generate + verify on another device returns the session and signs that device in
  console.log("\n[2] generate + verify...");
  const { client } = makeClient(baseURL);
  const email = `ott-${suffix}@example.com`;
  const user = await signUp(client, email);
  const gen = await client.oneTimeToken.generate();
  assert(!gen.error && typeof gen.data?.token === "string" && gen.data.token.length === 32, `generate failed: ${JSON.stringify(gen)}`);
  const { client: other, cookies: otherCookies } = makeClient(baseURL);
  const ver = await other.oneTimeToken.verify({ token: gen.data.token });
  assert(
    !ver.error && ver.data?.session?.token === user.token && ver.data?.user?.email === email && ver.data?.user?.id === user.user.id,
    `verify failed: ${JSON.stringify(ver)}`
  );
  assert(otherCookies.has("better-auth.session_token"), "verify should set the session cookie");
  const otherSession = await other.getSession();
  assert(otherSession.data?.user?.email === email, `verify should sign the device in, got ${JSON.stringify(otherSession.data)}`);

  // 3. a token works once
  console.log("\n[3] reuse...");
  const reuse = await other.oneTimeToken.verify({ token: gen.data.token });
  expectError(reuse, 400, "Invalid token", "verify reused token");
  const unknown = await other.oneTimeToken.verify({ token: "does-not-exist" });
  expectError(unknown, 400, "Invalid token", "verify unknown token");

  // 4. expired tokens are rejected
  console.log("\n[4] expiry...");
  const late = await client.oneTimeToken.generate();
  assert(!late.error, `generate failed: ${JSON.stringify(late)}`);
  const exp = await testJSON(baseURL, `/test/expire-ott?token=${encodeURIComponent(late.data.token)}`);
  assert(exp.updated === 1, `expire-ott did not update the token: ${JSON.stringify(exp)}`);
  const expired = await other.oneTimeToken.verify({ token: late.data.token });
  expectError(expired, 400, "Token expired", "verify expired token");

  // 5. hashed storage stores base64url(sha256(token))
  if (hashedURL) {
    console.log("\n[5] hashed storage...");
    const { client: h } = makeClient(hashedURL);
    await signUp(h, `ott-hash-${suffix}@example.com`);
    const hg = await h.oneTimeToken.generate();
    assert(!hg.error && hg.data?.token, `hashed generate failed: ${JSON.stringify(hg)}`);
    const { identifiers } = await testJSON(hashedURL, "/test/ott-identifiers");
    assert(identifiers.includes(`one-time-token:${defaultKeyHasher(hg.data.token)}`), `hashed identifier missing: ${JSON.stringify(identifiers)}`);
    assert(!identifiers.includes(`one-time-token:${hg.data.token}`), "plain token must not be stored in hashed mode");
    const { client: h2 } = makeClient(hashedURL);
    const hv = await h2.oneTimeToken.verify({ token: hg.data.token });
    assert(!hv.error && hv.data?.user?.email === `ott-hash-${suffix}@example.com`, `hashed verify failed: ${JSON.stringify(hv)}`);
  }

  // 6. disableClientRequest blocks generate from clients; server-side tokens still verify
  if (disabledURL) {
    console.log("\n[6] disableClientRequest...");
    const { client: d } = makeClient(disabledURL);
    const du = await signUp(d, `ott-disabled-${suffix}@example.com`);
    const dg = await d.oneTimeToken.generate();
    expectError(dg, 400, "Client requests are disabled", "generate with client requests disabled");
    const { token } = await testJSON(disabledURL, `/test/server-ott?sessionToken=${encodeURIComponent(du.token)}`);
    const { client: d2 } = makeClient(disabledURL);
    const dv = await d2.oneTimeToken.verify({ token });
    assert(!dv.error && dv.data?.session?.token === du.token, `verify of a server token failed: ${JSON.stringify(dv)}`);
  }

  console.log("\nAll one-time-token client checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
