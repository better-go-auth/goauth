import { createAuthClient } from "better-auth/client";
import { anonymousClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";

console.log("Running official better-auth/client anonymous test against:", baseURL);

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
    plugins: [anonymousClient()],
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

function expectError(res, code, status, label) {
  assert(res.error, `${label}: expected error ${code}, got data ${JSON.stringify(res.data)}`);
  assert(res.error.code === code, `${label}: expected code ${code}, got ${JSON.stringify(res.error)}`);
  if (status) assert(res.error.status === status, `${label}: expected status ${status}, got ${res.error.status}`);
}

// testState reads what the server's onLinkAccount saw and whether a user still exists.
async function testState(userID) {
  const res = await fetch(`${baseURL}/test/anonymous-state?user=${encodeURIComponent(userID || "")}`);
  assert(res.ok, `failed to fetch test state: ${res.status}`);
  return res.json();
}

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const password = "Password123!";

  // 1. signIn.anonymous creates an anonymous user and session
  console.log("\n[1] signIn.anonymous...");
  const { client } = makeClient(baseURL);
  const anon = await client.signIn.anonymous();
  assert(!anon.error && Boolean(anon.data?.token) && anon.data?.user?.isAnonymous === true, `signIn.anonymous failed: ${JSON.stringify(anon)}`);
  const anonID = anon.data.user.id;
  const sess = await client.getSession();
  assert(!sess.error && sess.data?.user?.id === anonID && sess.data?.user?.isAnonymous === true, `getSession: ${JSON.stringify(sess)}`);

  // 2. a second anonymous sign-in is rejected
  console.log("\n[2] signIn.anonymous again...");
  const again = await client.signIn.anonymous();
  expectError(again, "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY", 400, "second anonymous sign-in");

  // 3. signing up while anonymous links the account and deletes the anonymous user
  console.log("\n[3] signUp.email while anonymous (link)...");
  const up = await client.signUp.email({ email: `anon-${suffix}@example.com`, password, name: "Linked" });
  assert(!up.error && Boolean(up.data?.token) && !up.data?.user?.isAnonymous, `signUp failed: ${JSON.stringify(up)}`);
  const linked = await testState(anonID);
  assert(linked.links === 1 && linked.lastAnonymousUserId === anonID && linked.lastNewUserId === up.data.user.id,
    `onLinkAccount not called as expected: ${JSON.stringify(linked)}`);
  assert(linked.userExists === false, `anonymous user must be deleted: ${JSON.stringify(linked)}`);
  const sess2 = await client.getSession();
  assert(!sess2.error && sess2.data?.user?.id === up.data.user.id && !sess2.data?.user?.isAnonymous, `getSession after link: ${JSON.stringify(sess2)}`);

  // 4. a regular user is not anonymous: deleteAnonymousUser is forbidden
  console.log("\n[4] deleteAnonymousUser as a regular user...");
  const notAnon = await client.deleteAnonymousUser();
  expectError(notAnon, "USER_IS_NOT_ANONYMOUS", 403, "deleteAnonymousUser regular user");

  // 5. a fresh anonymous user deletes itself
  console.log("\n[5] deleteAnonymousUser...");
  const { client: c2 } = makeClient(baseURL);
  const anon2 = await c2.signIn.anonymous();
  assert(!anon2.error && anon2.data?.user?.isAnonymous === true, `second client signIn.anonymous failed: ${JSON.stringify(anon2)}`);
  const del = await c2.deleteAnonymousUser();
  assert(!del.error && del.data?.success === true, `deleteAnonymousUser failed: ${JSON.stringify(del)}`);
  const gone = await testState(anon2.data.user.id);
  assert(gone.userExists === false && gone.links === 1, `anonymous user must be deleted without linking: ${JSON.stringify(gone)}`);
  const sess3 = await c2.getSession();
  assert(!sess3.error && !sess3.data, `session must be gone after deleteAnonymousUser: ${JSON.stringify(sess3)}`);

  // 6. signing in to an existing account while anonymous also links
  console.log("\n[6] signIn.email while anonymous (link)...");
  const { client: c3 } = makeClient(baseURL);
  const anon3 = await c3.signIn.anonymous();
  assert(!anon3.error, `third signIn.anonymous failed: ${JSON.stringify(anon3)}`);
  const signIn = await c3.signIn.email({ email: `anon-${suffix}@example.com`, password });
  assert(!signIn.error && signIn.data?.user?.id === up.data.user.id, `signIn.email failed: ${JSON.stringify(signIn)}`);
  const linked2 = await testState(anon3.data.user.id);
  assert(linked2.links === 2 && linked2.lastAnonymousUserId === anon3.data.user.id && linked2.userExists === false,
    `second link not recorded: ${JSON.stringify(linked2)}`);

  console.log("\n✅ All official better-auth/client anonymous plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
