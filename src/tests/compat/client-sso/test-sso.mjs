// Official @better-auth/sso client test (better-auth 1.6.16 + @better-auth/sso 1.6.16) for goauth's sso plugin.
// The Go runner (src/tests/compat/ssoclient) starts a fake OIDC identity provider and goauth with the sso
// plugin, then runs this script with:
//   GOAUTH_URL         the goauth test server
//   GOAUTH_APP_BASE    goauth's configured BaseURL (redirect URIs and callback URLs use it)
//   SSO_ISSUER         the fake IdP's issuer (OIDC discovery runs at registration)
//   SSO_CLIENT_ID      / SSO_CLIENT_SECRET  the client registered at the fake IdP
//   SSO_PROVIDER_EMAIL the email of the fake IdP's user
//   SAML_CERT          a PEM certificate for the SAML provider registration
import { createAuthClient } from "better-auth/client";
import { ssoClient } from "@better-auth/sso/client";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const appBase = process.env.GOAUTH_APP_BASE || "http://localhost:3000";
const issuer = process.env.SSO_ISSUER;
const clientId = process.env.SSO_CLIENT_ID;
const clientSecret = process.env.SSO_CLIENT_SECRET;
const providerEmail = process.env.SSO_PROVIDER_EMAIL;
const samlCert = process.env.SAML_CERT;

console.log("Running official @better-auth/sso client test against:", baseURL, "issuer:", issuer);

function makeClient(url) {
  const cookies = new Map();
  const getCookieHeader = () => Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
  function saveCookies(response) {
    const list = response.headers.getSetCookie?.() || [];
    for (const str of list) {
      const parts = str.split(";")[0].split("=");
      const name = parts[0]?.trim();
      const value = parts.slice(1).join("=").trim();
      if (!name) continue;
      if (str.includes("Max-Age=0") || /Max-Age=-/.test(str) || value === "") cookies.delete(name);
      else cookies.set(name, value);
    }
  }
  const client = createAuthClient({
    baseURL: url,
    plugins: [ssoClient()],
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
  return { client, cookies, saveCookies, getCookieHeader };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

async function main() {
  const admin = makeClient(baseURL);

  // 1. an admin signs up and registers an OIDC provider (discovery at the fake IdP)
  console.log("\n[1] signUp + sso.register (OIDC)...");
  const su = await admin.client.signUp.email({ email: "admin@example.com", password: "password1234", name: "Admin" });
  assert(!su.error, `signUp: ${JSON.stringify(su.error)}`);
  const reg = await admin.client.sso.register({
    providerId: "fake-oidc",
    issuer,
    domain: "example.com",
    oidcConfig: { clientId, clientSecret },
  });
  assert(!reg.error, `sso.register: ${JSON.stringify(reg.error)}`);
  assert(reg.data.providerId === "fake-oidc" && reg.data.redirectURI === `${appBase}/api/auth/sso/callback/fake-oidc`, `register data: ${JSON.stringify(reg.data)}`);
  assert(reg.data.oidcConfig.tokenEndpoint === `${issuer}/token` && reg.data.oidcConfig.pkce === true, `discovered config: ${JSON.stringify(reg.data.oidcConfig)}`);

  // 2. duplicate registration is refused with better-auth's status and message
  const dup = await admin.client.sso.register({ providerId: "fake-oidc", issuer, domain: "example.com", oidcConfig: { clientId, clientSecret } });
  assert(dup.error?.status === 422 && dup.error.message === "SSO provider with this providerId already exists", `duplicate: ${JSON.stringify(dup.error)}`);

  // 3. a SAML provider, then the provider list (GET /sso/providers via the client's pathMethods)
  console.log("\n[3] sso.register (SAML) + sso.providers...");
  const samlReg = await admin.client.sso.register({
    providerId: "fake-saml",
    issuer: "https://idp.saml.example",
    domain: "saml.example",
    samlConfig: {
      entryPoint: "https://idp.saml.example/sso",
      cert: samlCert,
      callbackUrl: `${appBase}/api/auth/sso/saml2/callback/fake-saml`,
      spMetadata: { entityID: "https://sp.example" },
    },
  });
  assert(!samlReg.error && samlReg.data.samlConfig?.entryPoint === "https://idp.saml.example/sso", `saml register: ${JSON.stringify(samlReg)}`);
  const list = await admin.client.sso.providers();
  assert(!list.error, `sso.providers: ${JSON.stringify(list.error)}`);
  const ids = list.data.providers.map((p) => p.providerId).sort();
  assert(JSON.stringify(ids) === JSON.stringify(["fake-oidc", "fake-saml"]), `providers: ${JSON.stringify(list.data)}`);
  const oidc = list.data.providers.find((p) => p.providerId === "fake-oidc");
  assert(oidc.type === "oidc" && oidc.oidcConfig.clientIdLastFour === `****${clientId.slice(-4)}` && !("clientSecret" in oidc.oidcConfig), `sanitized: ${JSON.stringify(oidc)}`);
  const saml = list.data.providers.find((p) => p.providerId === "fake-saml");
  assert(saml.type === "saml" && saml.samlConfig.certificate.publicKeyAlgorithm === "RSA", `saml sanitized: ${JSON.stringify(saml)}`);
  const one = await admin.client.sso.getProvider({ query: { providerId: "fake-oidc" } });
  assert(!one.error && one.data.providerId === "fake-oidc", `getProvider: ${JSON.stringify(one)}`);

  // 4. SP metadata
  const md = await fetch(`${baseURL}/api/auth/sso/saml2/sp/metadata?providerId=fake-saml`);
  const mdText = await md.text();
  assert(md.status === 200 && md.headers.get("content-type") === "application/xml" && mdText.includes('entityID="https://sp.example"'), `metadata: ${md.status} ${mdText}`);

  // 5. SAML sign-in builds an AuthnRequest redirect with a relay state
  console.log("\n[5] signIn.sso (SAML)...");
  const user = makeClient(baseURL);
  const samlStart = await user.client.signIn.sso({ providerId: "fake-saml", callbackURL: `${appBase}/dashboard` });
  assert(!samlStart.error && samlStart.data.redirect === true, `saml signIn: ${JSON.stringify(samlStart)}`);
  const samlURL = new URL(samlStart.data.url);
  assert(samlURL.origin + samlURL.pathname === "https://idp.saml.example/sso" && samlURL.searchParams.get("SAMLRequest") && samlURL.searchParams.get("RelayState"), `AuthnRequest URL: ${samlStart.data.url}`);

  // 6. OIDC sign-in by email domain → fake IdP → goauth callback → session
  console.log("\n[6] signIn.sso (OIDC by email) → IdP → /sso/callback ...");
  const start = await user.client.signIn.sso({ email: providerEmail, callbackURL: `${appBase}/dashboard`, newUserCallbackURL: `${appBase}/welcome` });
  assert(!start.error && start.data.redirect === true, `signIn.sso: ${JSON.stringify(start)}`);
  const authURL = new URL(start.data.url);
  assert(authURL.searchParams.get("login_hint") === providerEmail && authURL.searchParams.get("code_challenge_method") === "S256", `authorization URL: ${start.data.url}`);
  const authRes = await fetch(start.data.url, { redirect: "manual" });
  assert(authRes.status === 302, `IdP authorize: ${authRes.status}`);
  const cbURL = authRes.headers.get("location");
  assert(cbURL.startsWith(`${baseURL}/api/auth/sso/callback/fake-oidc?`), `IdP redirect: ${cbURL}`);
  const cb = await fetch(cbURL, { redirect: "manual", headers: { cookie: user.getCookieHeader() } });
  user.saveCookies(cb);
  assert(cb.status === 302 && cb.headers.get("location") === `${appBase}/welcome`, `callback: ${cb.status} ${cb.headers.get("location")}`);

  // 7. the session belongs to the IdP user
  const sess = await user.client.getSession();
  assert(!sess.error && sess.data?.user?.email === providerEmail, `getSession: ${JSON.stringify(sess)}`);

  // 8. the SSO user cannot manage the admin's providers
  const denied = await user.client.sso.getProvider({ query: { providerId: "fake-oidc" } });
  assert(denied.error?.status === 403 && denied.error.message === "You don't have access to this provider", `access: ${JSON.stringify(denied.error)}`);

  // 9. the admin deletes the SAML provider
  const del = await admin.client.sso.deleteProvider({ providerId: "fake-saml" });
  assert(!del.error && del.data.success === true, `deleteProvider: ${JSON.stringify(del)}`);

  console.log("\nALL SSO CLIENT CHECKS PASSED");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
