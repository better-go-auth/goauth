import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { oneTimeTokenClient, usernameClient } from "better-auth/client/plugins";
import { oneTimeToken, openAPI, username } from "better-auth/plugins";

// goauth runs with BaseURL http://localhost:3000 and the open-api, one-time-token and username plugins.
// The same setup is built here with better-auth itself (no database is needed to generate the document),
// and goauth's document and reference page are compared with better-auth's.
const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const publicURL = "http://localhost:3000";

console.log("Running official better-auth/client open-api test against:", baseURL);

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

// canonical sorts object keys (and the `required` arrays, whose order is not meaningful) for comparison.
function canonical(v, key) {
  if (Array.isArray(v)) {
    const items = v.map((x) => canonical(x));
    return key === "required" ? items.sort() : items;
  }
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k], k)]));
  }
  return v;
}

function same(a, b, label) {
  const ja = JSON.stringify(canonical(a));
  const jb = JSON.stringify(canonical(b));
  assert(ja === jb, `${label} differs:\n goauth:      ${ja}\n better-auth: ${jb}`);
}

async function main() {
  const client = createAuthClient({
    baseURL,
    plugins: [oneTimeTokenClient(), usernameClient()],
    fetchOptions: { onRequest: (ctx) => ctx.headers.set("origin", publicURL) },
  });
  const reference = betterAuth({
    baseURL: publicURL,
    secret: "open-api-compat-secret-0123456789abcdefghijklmnop",
    emailAndPassword: { enabled: true },
    plugins: [openAPI(), oneTimeToken(), username()],
    logger: { disabled: true },
  });
  const expected = await reference.api.generateOpenAPISchema();

  // 1. the document through the official client
  console.log("\n[1] generate-schema...");
  const res = await client.$fetch("/open-api/generate-schema", { method: "GET" });
  assert(!res.error, `generate-schema failed: ${JSON.stringify(res.error)}`);
  const doc = res.data;

  // 2. the envelope is better-auth's
  console.log("\n[2] envelope...");
  for (const key of ["openapi", "info", "security", "servers", "tags"]) same(doc[key], expected[key], key);
  same(doc.components.securitySchemes, expected.components.securitySchemes, "securitySchemes");

  // 3. the table schemas are better-auth's (core tables + the username plugin's user fields)
  console.log("\n[3] components.schemas...");
  same(Object.keys(doc.components.schemas).sort(), Object.keys(expected.components.schemas).sort(), "schema names");
  for (const name of Object.keys(expected.components.schemas)) {
    same(doc.components.schemas[name], expected.components.schemas[name], `components.schemas.${name}`);
  }

  // 4. paths: every documented route uses better-auth's conventions
  console.log("\n[4] paths...");
  const shared = Object.keys(doc.paths).filter((p) => expected.paths[p]);
  assert(shared.length >= 15, `too few shared paths: ${shared}`);
  for (const p of shared) {
    for (const method of Object.keys(expected.paths[p])) {
      const ours = doc.paths[p][method];
      assert(ours, `${method.toUpperCase()} ${p} missing in goauth's document`);
      same(ours.tags, expected.paths[p][method].tags, `tags of ${method} ${p}`);
      same(ours.security, expected.paths[p][method].security, `security of ${method} ${p}`);
      // better-auth's default error responses (endpoints that document their own errors keep them; goauth
      // has the defaults there)
      for (const code of ["400", "401", "403", "404", "429", "500"]) {
        const theirs = expected.paths[p][method].responses[code];
        assert(ours.responses[code], `${code} response of ${method} ${p} missing`);
        if (theirs?.description === ours.responses[code].description) same(ours.responses[code], theirs, `${code} of ${method} ${p}`);
      }
    }
  }
  for (const p of ["/sign-in/email", "/sign-up/email", "/get-session", "/one-time-token/generate", "/sign-in/username"]) {
    assert(doc.paths[p], `missing ${p}`);
  }
  assert(!doc.paths["/open-api/generate-schema"] && !doc.paths["/reference"], "the plugin's own routes are not documented");
  assert(!JSON.stringify(doc).includes("$ref"), "the document must be self-contained");
  const ids = Object.values(doc.paths).flatMap((item) => Object.values(item).map((op) => op.operationId)).filter(Boolean);
  assert(new Set(ids).size === ids.length, "operation IDs are unique");

  // 5. the reference page is better-auth's page around goauth's document
  console.log("\n[5] reference page...");
  const page = await fetch(`${baseURL}/api/auth/reference`);
  assert(page.status === 200 && page.headers.get("content-type").startsWith("text/html"), `reference: ${page.status}`);
  const html = await page.text();
  const expectedPage = await (await reference.handler(new Request(`${publicURL}/api/auth/reference`))).text();
  const embedded = /(<script\s+id="api-reference"\s+type="application\/json">\s*)([\s\S]*?)(\s*<\/script>)/;
  const ours = html.match(embedded);
  assert(ours, "no embedded document in goauth's page");
  same(JSON.parse(ours[2]), doc, "embedded document");
  // with goauth's embedded JSON put into better-auth's page, both pages are byte for byte equal
  assert(html === expectedPage.replace(embedded, (_, a, __, c) => a + ours[2] + c), "the page differs from better-auth's");
}

main().then(
  () => console.log("\nAll open-api client checks passed"),
  (e) => {
    console.error(e);
    process.exit(1);
  },
);
