import { createAuthClient } from "better-auth/client";
import { inferAdditionalFields } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";

console.log("Running official better-auth/client additionalFields test against:", baseURL);

// makeClient returns a client keeping cookies like a browser (fetch in Node has no cookie jar).
function makeClient(url) {
  const cookies = new Map();

  function cookieHeader() {
    return Array.from(cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }

  function saveCookies(response) {
    const list = response.headers.getSetCookie?.() || [];
    for (const str of list) {
      const [pair] = str.split(";");
      const idx = pair.indexOf("=");
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      if (!name) continue;
      if (str.includes("Max-Age=0")) cookies.delete(name);
      else cookies.set(name, value);
    }
  }

  // the same schema the Go test server declares (user.additionalFields / session.additionalFields)
  const client = createAuthClient({
    baseURL: url,
    plugins: [
      inferAdditionalFields({
        user: {
          plan: { type: "string", required: false },
          age: { type: "number", required: false },
          tags: { type: "string[]", required: false },
          credits: { type: "number", input: false },
          verifiedPro: { type: "boolean", input: false },
        },
        session: {
          deviceLabel: { type: "string", required: false },
        },
      }),
    ],
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
  const email = `fields_${suffix}@example.com`;
  const password = "Password123!";
  const { client } = makeClient(baseURL);

  // 1. signUp.email with additional fields
  console.log("\n[1] signUp.email with additional fields...");
  const up = await client.signUp.email({ email, password, name: "Fields", plan: "pro", age: 30, tags: ["a", "b"] });
  assert(!up.error, `signUp failed: ${JSON.stringify(up.error)}`);
  assert(up.data.user.plan === "pro", `user.plan: ${JSON.stringify(up.data.user)}`);
  assert(up.data.user.age === 30, `user.age: ${JSON.stringify(up.data.user)}`);
  assert(JSON.stringify(up.data.user.tags) === '["a","b"]', `user.tags: ${JSON.stringify(up.data.user)}`);
  assert(up.data.user.credits === 10, `input:false default: ${JSON.stringify(up.data.user)}`);
  assert(up.data.user.verifiedPro === null, `unset field is null: ${JSON.stringify(up.data.user)}`);
  assert(!("secretNote" in up.data.user), "returned:false field must be hidden");

  // 2. getSession returns them
  console.log("\n[2] getSession...");
  let session = await client.getSession();
  assert(!session.error && session.data, `getSession failed: ${JSON.stringify(session.error)}`);
  assert(session.data.user.plan === "pro", `session user.plan: ${JSON.stringify(session.data.user)}`);
  assert(session.data.session.deviceLabel === null, `session.deviceLabel: ${JSON.stringify(session.data.session)}`);
  assert(session.data.session.trusted === false, `session.trusted default: ${JSON.stringify(session.data.session)}`);

  // 3. updateUser changes them
  console.log("\n[3] updateUser...");
  const upd = await client.updateUser({ plan: "team", age: 31 });
  assert(!upd.error && upd.data?.status === true, `updateUser failed: ${JSON.stringify(upd.error)}`);
  session = await client.getSession();
  assert(session.data.user.plan === "team", `updated plan: ${JSON.stringify(session.data.user)}`);
  assert(session.data.user.age === 31, `updated age: ${JSON.stringify(session.data.user)}`);

  // 4. input:false fields are rejected (better-auth's FIELD_NOT_ALLOWED)
  console.log("\n[4] input:false rejection...");
  expectError(await client.updateUser({ verifiedPro: true }), "FIELD_NOT_ALLOWED", 400, "updateUser input:false");
  expectError(await client.updateUser({ credits: 99 }), "FIELD_NOT_ALLOWED", 400, "updateUser input:false with default");
  const { client: other } = makeClient(baseURL);
  expectError(
    await other.signUp.email({ email: `other_${suffix}@example.com`, password, name: "Other", verifiedPro: true }),
    "FIELD_NOT_ALLOWED",
    400,
    "signUp input:false",
  );

  // 5. validation error and unknown keys
  console.log("\n[5] validation and unknown keys...");
  expectError(await client.updateUser({ age: 5 }), "VALIDATION_ERROR", 400, "validator");
  expectError(await client.updateUser({ notAField: 1 }), "NO_FIELDS_TO_UPDATE", 400, "nothing to update");

  // 6. updateSession with a session additional field
  console.log("\n[6] updateSession...");
  const us = await client.updateSession({ deviceLabel: "Laptop" });
  assert(!us.error, `updateSession failed: ${JSON.stringify(us.error)}`);
  assert(us.data.session.deviceLabel === "Laptop", `updateSession response: ${JSON.stringify(us.data)}`);
  session = await client.getSession();
  assert(session.data.session.deviceLabel === "Laptop", `session.deviceLabel: ${JSON.stringify(session.data.session)}`);

  // 7. signIn.email returns the fields too
  console.log("\n[7] signIn.email...");
  await client.signOut();
  const inRes = await client.signIn.email({ email, password });
  assert(!inRes.error, `signIn failed: ${JSON.stringify(inRes.error)}`);
  assert(inRes.data.user.plan === "team", `signIn user.plan: ${JSON.stringify(inRes.data.user)}`);

  console.log("\nAll additionalFields client checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
