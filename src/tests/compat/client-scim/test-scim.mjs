// Official @better-auth/scim client test (better-auth 1.6.16 + @better-auth/scim 1.6.16) for goauth's scim plugin.
// The management endpoints go through createAuthClient + scimClient(); the SCIM 2.0 endpoints are called with
// fetch and the bearer SCIM token, like an identity provider does. Environment:
//   GOAUTH_URL  the goauth test server
import { createAuthClient } from "better-auth/client";
import { scimClient } from "@better-auth/scim/client";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const scimBase = `${baseURL}/api/auth/scim/v2`;
console.log("Running official @better-auth/scim client test against:", baseURL);

function makeClient(url) {
  const cookies = new Map();
  const getCookieHeader = () => Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
  const client = createAuthClient({
    baseURL: url,
    plugins: [scimClient()],
    fetchOptions: {
      onRequest(ctx) {
        ctx.headers.set("origin", url);
        const c = getCookieHeader();
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        for (const str of ctx.response.headers.getSetCookie?.() || []) {
          const parts = str.split(";")[0].split("=");
          const name = parts[0]?.trim();
          const value = parts.slice(1).join("=").trim();
          if (!name) continue;
          if (str.includes("Max-Age=0") || value === "") cookies.delete(name);
          else cookies.set(name, value);
        }
      },
    },
  });
  return { client };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

async function scim(method, path, token, body) {
  const headers = { accept: "application/scim+json" };
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/scim+json";
  const res = await fetch(`${scimBase}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : null };
}

async function main() {
  const { client } = makeClient(baseURL);

  // 1. an admin signs up and generates a SCIM token
  console.log("\n[1] signUp + scim.generateToken...");
  const su = await client.signUp.email({ email: "admin@corp.example", password: "password1234", name: "Admin" });
  assert(!su.error, `signUp: ${JSON.stringify(su.error)}`);
  const gen = await client.scim.generateToken({ providerId: "okta" });
  assert(!gen.error && typeof gen.data.scimToken === "string", `generateToken: ${JSON.stringify(gen)}`);
  const token = gen.data.scimToken;
  const decoded = Buffer.from(token, "base64url").toString();
  assert(decoded.endsWith(":okta") && decoded.split(":")[0].length === 24, `token payload: ${decoded}`);
  const bad = await client.scim.generateToken({ providerId: "a:b" });
  assert(bad.error?.status === 400 && bad.error.message === "Provider id contains forbidden characters", `forbidden id: ${JSON.stringify(bad.error)}`);

  // 2. connections through the client (GET inferred from the missing body)
  const conns = await client.scim.listProviderConnections();
  assert(!conns.error && conns.data.providers.length === 1 && conns.data.providers[0].providerId === "okta" && conns.data.providers[0].organizationId === null, `connections: ${JSON.stringify(conns)}`);
  const conn = await client.scim.getProviderConnection({ query: { providerId: "okta" } });
  assert(!conn.error && conn.data.providerId === "okta", `connection: ${JSON.stringify(conn)}`);

  // 3. metadata endpoints
  console.log("\n[3] SCIM metadata...");
  const spc = await scim("GET", "/ServiceProviderConfig");
  assert(spc.status === 200 && spc.body.patch.supported === true && spc.body.filter.supported === true, `ServiceProviderConfig: ${JSON.stringify(spc.body)}`);
  const schemas = await scim("GET", "/Schemas");
  assert(schemas.body.Resources[0].id === "urn:ietf:params:scim:schemas:core:2.0:User", `Schemas: ${JSON.stringify(schemas.body)}`);
  const types = await scim("GET", "/ResourceTypes/User");
  assert(types.body.endpoint === "/Users", `ResourceType: ${JSON.stringify(types.body)}`);

  // 4. users: create, conflict, list with filter, get, PUT, PATCH, DELETE
  console.log("\n[4] SCIM users...");
  const created = await scim("POST", "/Users", token, { userName: "grace@corp.example", externalId: "g-1", name: { givenName: "Grace", familyName: "Hopper" } });
  assert(created.status === 201 && created.headers.get("location") === created.body.meta.location, `create: ${created.status} ${JSON.stringify(created.body)}`);
  assert(created.body.displayName === "Grace Hopper" && created.body.active === true && created.body.externalId === "g-1", `resource: ${JSON.stringify(created.body)}`);
  const id = created.body.id;
  const conflict = await scim("POST", "/Users", token, { userName: "grace@corp.example", externalId: "g-1" });
  assert(conflict.status === 409 && conflict.body.scimType === "uniqueness" && conflict.body.status === "409" && conflict.body.schemas[0] === "urn:ietf:params:scim:api:messages:2.0:Error", `conflict: ${JSON.stringify(conflict.body)}`);
  const list = await scim("GET", `/Users?filter=${encodeURIComponent('userName eq "GRACE@corp.example"')}`, token);
  assert(list.status === 200 && list.body.totalResults === 1 && list.body.Resources[0].id === id, `list: ${JSON.stringify(list.body)}`);
  const badFilter = await scim("GET", `/Users?filter=${encodeURIComponent('userName co "g"')}`, token);
  assert(badFilter.status === 400 && badFilter.body.scimType === "invalidFilter", `bad filter: ${JSON.stringify(badFilter.body)}`);
  const put = await scim("PUT", `/Users/${id}`, token, { userName: "grace.h@corp.example", name: { formatted: "Rear Admiral Hopper" } });
  assert(put.status === 200 && put.body.userName === "grace.h@corp.example" && put.body.displayName === "Rear Admiral Hopper", `put: ${JSON.stringify(put.body)}`);
  const patch = await scim("PATCH", `/Users/${id}`, token, { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "replace", path: "name.givenName", value: "Amazing" }] });
  assert(patch.status === 204, `patch: ${patch.status} ${JSON.stringify(patch.body)}`);
  const got = await scim("GET", `/Users/${id}`, token);
  assert(got.body.displayName === "Amazing Admiral Hopper", `after patch: ${JSON.stringify(got.body)}`);
  const unauth = await scim("GET", "/Users", "not-a-token");
  assert(unauth.status === 401 && unauth.body.detail === "Invalid SCIM token", `unauthorized: ${JSON.stringify(unauth.body)}`);
  const del = await scim("DELETE", `/Users/${id}`, token);
  assert(del.status === 204, `delete: ${del.status}`);
  const gone = await scim("GET", `/Users/${id}`, token);
  assert(gone.status === 404 && gone.body.detail === "User not found", `gone: ${JSON.stringify(gone.body)}`);

  // 5. deleting the connection revokes the token
  const rm = await client.scim.deleteProviderConnection({ providerId: "okta" });
  assert(!rm.error && rm.data.success === true, `deleteProviderConnection: ${JSON.stringify(rm)}`);
  const revoked = await scim("GET", "/Users", token);
  assert(revoked.status === 401, `revoked token: ${revoked.status}`);

  console.log("\nALL SCIM CLIENT CHECKS PASSED");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
