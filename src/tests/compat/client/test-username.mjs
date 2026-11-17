import { createAuthClient } from "better-auth/client";
import { usernameClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";

console.log("Running official better-auth/client username test against:", baseURL);

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
    plugins: [usernameClient()],
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

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const name = `User_${suffix}`;
  const lower = name.toLowerCase();
  const password = "Password123!";

  // 1. signUp.email with a username: normalized username, original displayUsername
  console.log("\n[1] signUp.email with username...");
  const { client } = makeClient(baseURL);
  const up = await client.signUp.email({ email: `user-${suffix}@example.com`, password, name: "Username User", username: name });
  assert(!up.error && Boolean(up.data?.token), `signUp failed: ${JSON.stringify(up)}`);
  assert(up.data.user.username === lower && up.data.user.displayUsername === name, `signUp user fields: ${JSON.stringify(up.data.user)}`);
  const userID = up.data.user.id;

  // 2. getSession reports the username fields
  console.log("\n[2] getSession...");
  const sess = await client.getSession();
  assert(!sess.error && sess.data?.user?.username === lower && sess.data?.user?.displayUsername === name, `getSession: ${JSON.stringify(sess)}`);

  // 3. duplicate and invalid usernames on sign-up
  console.log("\n[3] signUp.email duplicate / invalid username...");
  const { client: c2 } = makeClient(baseURL);
  const dup = await c2.signUp.email({ email: `dup-${suffix}@example.com`, password, name: "Dup", username: name.toUpperCase() });
  expectError(dup, "USERNAME_IS_ALREADY_TAKEN", 400, "duplicate username");
  const short = await c2.signUp.email({ email: `short-${suffix}@example.com`, password, name: "Short", username: "ab" });
  expectError(short, "USERNAME_TOO_SHORT", 400, "short username");
  const invalid = await c2.signUp.email({ email: `inv-${suffix}@example.com`, password, name: "Invalid", username: "bad name!" });
  expectError(invalid, "INVALID_USERNAME", 400, "invalid username");

  // 4. signIn.username (case-insensitive), wrong password, unknown user
  console.log("\n[4] signIn.username...");
  const { client: c3 } = makeClient(baseURL);
  const wrong = await c3.signIn.username({ username: lower, password: "wrong-password" });
  expectError(wrong, "INVALID_USERNAME_OR_PASSWORD", 401, "wrong password");
  const unknown = await c3.signIn.username({ username: `nobody_${suffix}`, password });
  expectError(unknown, "INVALID_USERNAME_OR_PASSWORD", 401, "unknown user");
  const tooShort = await c3.signIn.username({ username: "ab", password });
  expectError(tooShort, "USERNAME_TOO_SHORT", 422, "sign-in short username");
  const signIn = await c3.signIn.username({ username: name.toUpperCase(), password });
  assert(!signIn.error && Boolean(signIn.data?.token) && signIn.data?.redirect === false && signIn.data?.user?.id === userID,
    `signIn.username failed: ${JSON.stringify(signIn)}`);
  const sess3 = await c3.getSession();
  assert(!sess3.error && sess3.data?.user?.id === userID, `getSession after signIn.username: ${JSON.stringify(sess3)}`);

  // 5. isUsernameAvailable
  console.log("\n[5] isUsernameAvailable...");
  const taken = await c2.isUsernameAvailable({ username: name });
  assert(!taken.error && taken.data?.available === false, `isUsernameAvailable(taken): ${JSON.stringify(taken)}`);
  const free = await c2.isUsernameAvailable({ username: `free_${suffix}` });
  assert(!free.error && free.data?.available === true, `isUsernameAvailable(free): ${JSON.stringify(free)}`);
  const bad = await c2.isUsernameAvailable({ username: "x" });
  expectError(bad, "USERNAME_TOO_SHORT", 422, "isUsernameAvailable short");

  // 6. updateUser changes the username; another user's username is taken
  console.log("\n[6] updateUser username...");
  const newName = `New.${suffix}`;
  const upd = await client.updateUser({ username: newName, displayUsername: newName });
  assert(!upd.error && upd.data?.status === true, `updateUser failed: ${JSON.stringify(upd)}`);
  const sess4 = await client.getSession({ query: { disableCookieCache: true } });
  assert(!sess4.error && sess4.data?.user?.username === newName.toLowerCase() && sess4.data?.user?.displayUsername === newName,
    `getSession after updateUser: ${JSON.stringify(sess4)}`);
  const other = await c2.signUp.email({ email: `other-${suffix}@example.com`, password, name: "Other", username: `other_${suffix}` });
  assert(!other.error, `signUp other failed: ${JSON.stringify(other.error)}`);
  const conflict = await c2.updateUser({ username: newName.toUpperCase() });
  expectError(conflict, "USERNAME_IS_ALREADY_TAKEN", 400, "updateUser conflict");
  const same = await client.updateUser({ username: newName });
  assert(!same.error, `updateUser to own username failed: ${JSON.stringify(same.error)}`);

  // 7. the new username signs in, the old one does not
  console.log("\n[7] signIn.username after rename...");
  const { client: c4 } = makeClient(baseURL);
  const old = await c4.signIn.username({ username: lower, password });
  expectError(old, "INVALID_USERNAME_OR_PASSWORD", 401, "old username");
  const renamed = await c4.signIn.username({ username: newName, password });
  assert(!renamed.error && renamed.data?.user?.id === userID, `signIn with new username: ${JSON.stringify(renamed)}`);

  console.log("\n✅ All official better-auth/client username plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
