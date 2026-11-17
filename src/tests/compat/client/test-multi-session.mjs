import { createAuthClient } from "better-auth/client";
import { multiSessionClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const max2URL = process.env.GOAUTH_URL_MAX2;

console.log("Running official better-auth/client multi-session test against:", baseURL);

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
    plugins: [multiSessionClient()],
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

function expectError(res, code, status, label) {
  assert(res.error, `${label}: expected error ${code}, got data ${JSON.stringify(res.data)}`);
  assert(res.error.code === code, `${label}: expected code ${code}, got ${JSON.stringify(res.error)}`);
  if (status) assert(res.error.status === status, `${label}: expected status ${status}, got ${res.error.status}`);
}

function multiCookies(cookies) {
  return Array.from(cookies.keys()).filter((k) => k.includes("_multi-"));
}

const password = "MultiPass123!";

async function signUp(client, email) {
  const res = await client.signUp.email({ email, password, name: email.split("@")[0] });
  assert(!res.error && res.data?.token, `signUp ${email} failed: ${JSON.stringify(res)}`);
  return res.data;
}

function emails(list) {
  return (list || []).map((s) => s.user.email).sort().join(",");
}

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const emailA = `ms-a-${suffix}@example.com`;
  const emailB = `ms-b-${suffix}@example.com`;
  const { client, cookies } = makeClient(baseURL);

  // 1. two users signing in on one device get one multi-session cookie each
  console.log("\n[1] two users sign in on one device...");
  const a = await signUp(client, emailA);
  const b = await signUp(client, emailB);
  assert(cookies.has(`better-auth.session_token_multi-${a.token.toLowerCase()}`), `missing multi cookie for A: ${multiCookies(cookies)}`);
  assert(cookies.has(`better-auth.session_token_multi-${b.token.toLowerCase()}`), `missing multi cookie for B: ${multiCookies(cookies)}`);

  // 2. listDeviceSessions shows both, getSession shows the last one
  console.log("\n[2] listDeviceSessions...");
  const list = await client.multiSession.listDeviceSessions();
  assert(!list.error && Array.isArray(list.data) && list.data.length === 2, `listDeviceSessions failed: ${JSON.stringify(list)}`);
  assert(emails(list.data) === [emailA, emailB].sort().join(","), `unexpected device sessions: ${emails(list.data)}`);
  assert(list.data.every((s) => s.session?.token && s.session?.userId === s.user?.id), `bad session shape: ${JSON.stringify(list.data)}`);
  const sess = await client.getSession();
  assert(sess.data?.user?.email === emailB, `active user should be B, got ${JSON.stringify(sess.data)}`);

  // 3. setActive switches the active session
  console.log("\n[3] setActive...");
  const active = await client.multiSession.setActive({ sessionToken: a.token });
  assert(!active.error && active.data?.user?.email === emailA && active.data?.session?.token === a.token, `setActive failed: ${JSON.stringify(active)}`);
  const sessA = await client.getSession();
  assert(sessA.data?.user?.email === emailA, `active user should be A after setActive, got ${JSON.stringify(sessA.data)}`);
  const badActive = await client.multiSession.setActive({ sessionToken: "not-a-device-session" });
  expectError(badActive, "INVALID_SESSION_TOKEN", 401, "setActive unknown token");

  // 4. revoke removes a device session
  console.log("\n[4] revoke...");
  const badRevoke = await client.multiSession.revoke({ sessionToken: "not-a-device-session" });
  expectError(badRevoke, "INVALID_SESSION_TOKEN", 401, "revoke unknown token");
  const revoked = await client.multiSession.revoke({ sessionToken: b.token });
  assert(!revoked.error && revoked.data?.status === true, `revoke failed: ${JSON.stringify(revoked)}`);
  const afterRevoke = await client.multiSession.listDeviceSessions();
  assert(emails(afterRevoke.data) === emailA, `device sessions after revoke: ${emails(afterRevoke.data)}`);
  assert(!cookies.has(`better-auth.session_token_multi-${b.token.toLowerCase()}`), "revoked multi cookie not cleared");
  const stillA = await client.getSession();
  assert(stillA.data?.user?.email === emailA, `revoking B must keep A active, got ${JSON.stringify(stillA.data)}`);

  // 5. revoking the active session falls back to another device session
  console.log("\n[5] revoke the active session...");
  const b2 = (await client.signIn.email({ email: emailB, password })).data;
  assert(b2?.token, "signIn B failed");
  const back = await client.multiSession.revoke({ sessionToken: b2.token });
  assert(!back.error && back.data?.status === true, `revoke active failed: ${JSON.stringify(back)}`);
  const fallback = await client.getSession();
  assert(fallback.data?.user?.email === emailA, `active user after revoking the active one should be A, got ${JSON.stringify(fallback.data)}`);

  // 6. signOut revokes and clears every device session
  console.log("\n[6] signOut...");
  const b3 = (await client.signIn.email({ email: emailB, password })).data;
  assert(b3?.token, "signIn B again failed");
  const savedMulti = new Map(Array.from(cookies.entries()).filter(([k]) => k.includes("_multi-")));
  assert(savedMulti.size === 2, `expected 2 multi cookies before signOut, got ${savedMulti.size}`);
  const out = await client.signOut();
  assert(!out.error, `signOut failed: ${JSON.stringify(out)}`);
  assert(multiCookies(cookies).length === 0, `multi cookies left after signOut: ${multiCookies(cookies)}`);
  const none = await client.getSession();
  assert(!none.data, `still signed in after signOut: ${JSON.stringify(none.data)}`);
  // replaying the old multi cookies lists nothing: the sessions were revoked
  const { client: replay, cookies: replayCookies } = makeClient(baseURL);
  for (const [k, v] of savedMulti) replayCookies.set(k, v);
  const replayList = await replay.multiSession.listDeviceSessions();
  assert(!replayList.error && replayList.data?.length === 0, `revoked sessions still listed: ${JSON.stringify(replayList)}`);

  // 7. maximumSessions limits the multi-session cookies of a device
  if (max2URL) {
    console.log("\n[7] maximumSessions = 2...");
    const { client: limited, cookies: limitedCookies } = makeClient(max2URL);
    await signUp(limited, `max-x-${suffix}@example.com`);
    await signUp(limited, `max-y-${suffix}@example.com`);
    const z = await signUp(limited, `max-z-${suffix}@example.com`);
    assert(multiCookies(limitedCookies).length === 2, `expected 2 multi cookies, got ${multiCookies(limitedCookies)}`);
    assert(!limitedCookies.has(`better-auth.session_token_multi-${z.token.toLowerCase()}`), "session over the maximum got a multi cookie");
    const limitedList = await limited.multiSession.listDeviceSessions();
    assert(limitedList.data?.length === 2, `expected 2 device sessions, got ${JSON.stringify(limitedList.data)}`);
    const zActive = await limited.getSession();
    assert(zActive.data?.user?.email === `max-z-${suffix}@example.com`, "the newest session should still be active");
  }

  console.log("\nAll multi-session client checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
