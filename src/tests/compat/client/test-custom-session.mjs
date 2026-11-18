// Official better-auth client (customSessionClient + multiSessionClient) against goauth's custom-session
// plugin. The Go runner configures a callback returning {roles, user: {...user, newField}, session}.
import { createAuthClient } from "better-auth/client";
import { customSessionClient, multiSessionClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";

console.log("Running official better-auth/client custom-session test against:", baseURL);

function makeClient(url) {
  const cookies = new Map();
  const client = createAuthClient({
    baseURL: url,
    plugins: [customSessionClient(), multiSessionClient()],
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", url);
        const c = Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        for (const str of ctx.response.headers.getSetCookie?.() || []) {
          const [pair] = str.split(";");
          const i = pair.indexOf("=");
          const name = pair.slice(0, i).trim();
          if (str.includes("Max-Age=0")) cookies.delete(name);
          else cookies.set(name, pair.slice(i + 1).trim());
        }
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

async function main() {
  const suffix = String(Date.now()).slice(-7);
  const password = "Password123!";
  const { client } = makeClient(baseURL);

  // 1. no session → null
  console.log("\n[1] getSession without a session...");
  const anon = await client.getSession();
  assert(!anon.error && anon.data === null, `anonymous getSession: ${JSON.stringify(anon)}`);

  // 2. the custom session
  console.log("\n[2] getSession after signUp...");
  const email = `custom-${suffix}@example.com`;
  const up = await client.signUp.email({ email, password, name: "Custom" });
  assert(!up.error, `signUp: ${JSON.stringify(up.error)}`);
  const sess = await client.getSession();
  assert(!sess.error, `getSession: ${JSON.stringify(sess.error)}`);
  const d = sess.data;
  assert(Array.isArray(d?.roles) && d.roles[0] === "editor", `roles: ${JSON.stringify(d)}`);
  assert(d.user?.email === email && d.user?.newField === "custom", `user: ${JSON.stringify(d.user)}`);
  assert(typeof d.session?.token === "string" && d.session.userId === d.user.id, `session: ${JSON.stringify(d.session)}`);

  // 3. disableCookieCache query still goes through the callback
  console.log("\n[3] getSession({ query: { disableCookieCache: true } })...");
  const fresh = await client.getSession({ query: { disableCookieCache: true } });
  assert(!fresh.error && fresh.data?.roles?.[0] === "editor", `fresh: ${JSON.stringify(fresh)}`);

  // 4. multi-session list mapped through the callback (shouldMutateListDeviceSessionsEndpoint)
  console.log("\n[4] multiSession.listDeviceSessions...");
  const up2 = await client.signUp.email({ email: `custom2-${suffix}@example.com`, password, name: "Second" });
  assert(!up2.error, `second signUp: ${JSON.stringify(up2.error)}`);
  const list = await client.multiSession.listDeviceSessions();
  assert(!list.error && Array.isArray(list.data) && list.data.length === 2, `list: ${JSON.stringify(list)}`);
  assert(list.data.every((s) => s.roles?.[0] === "editor" && s.user?.newField === "custom"), `list entries: ${JSON.stringify(list.data)}`);

  console.log("\n✅ All official better-auth/client custom-session plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
