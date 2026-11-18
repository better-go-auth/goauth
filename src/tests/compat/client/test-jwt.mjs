import { createAuthClient } from "better-auth/client";
import { jwtClient } from "better-auth/client/plugins";
import { importJWK, jwtVerify } from "jose";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
console.log("Running official better-auth/client JWT test against:", baseURL);

let currentBearerToken = "";
let lastSetAuthJwt = "";

const client = createAuthClient({
  baseURL,
  plugins: [
    jwtClient()
  ],
  fetchOptions: {
    auth: {
      type: "Bearer",
      token: () => currentBearerToken,
    },
    onRequest(ctx) {
      ctx.headers.set("origin", baseURL);
    },
    onSuccess(ctx) {
      const authToken = ctx.response.headers.get("set-auth-token");
      if (authToken) {
        currentBearerToken = authToken;
      }
      const authJwt = ctx.response.headers.get("set-auth-jwt");
      if (authJwt) {
        lastSetAuthJwt = authJwt;
      }
    },
    onResponse(ctx) {
      const authToken = ctx.response.headers.get("set-auth-token");
      if (authToken) {
        currentBearerToken = authToken;
      }
      const authJwt = ctx.response.headers.get("set-auth-jwt");
      if (authJwt) {
        lastSetAuthJwt = authJwt;
      }
    },
  },
});

async function main() {
  const ts = Date.now();
  const email = `jwt-client-${ts}@example.com`;
  const password = "Password123!";
  const name = "Official Client JWT User";

  // 1. Test client.jwks() using the official client plugin
  console.log("\n[1] Testing client.jwks() using jwtClient plugin...");
  const jwksRes = await client.jwks();
  if (jwksRes.error) {
    console.error("client.jwks() failed:", jwksRes.error);
    process.exit(1);
  }
  const keys = jwksRes.data?.keys;
  console.log("JWKS keys retrieved:", JSON.stringify(keys, null, 2));
  if (!Array.isArray(keys) || keys.length === 0) {
    console.error("Expected array of keys in JWKS response, got:", keys);
    process.exit(1);
  }
  const jwk = keys[0];
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x || !jwk.kid) {
    console.error("Invalid JWK key structure:", jwk);
    process.exit(1);
  }
  const importedKey = await importJWK(jwk, "EdDSA");
  console.log("Successfully imported public JWK into jose!");

  // 2. Sign up user
  console.log("\n[2] Testing client.signUp.email...");
  const signUpRes = await client.signUp.email({
    email,
    password,
    name,
  });
  if (signUpRes.error) {
    console.error("signUp.email failed:", signUpRes.error);
    process.exit(1);
  }
  console.log("User registered:", signUpRes.data?.user?.email);
  if (!currentBearerToken) {
    console.error("No set-auth-token captured from sign-up response!");
    process.exit(1);
  }

  // 3. Test getSession() and set-auth-jwt header emission
  console.log("\n[3] Testing client.getSession() and set-auth-jwt response header...");
  const sessionRes = await client.getSession();
  if (sessionRes.error) {
    console.error("getSession failed:", sessionRes.error);
    process.exit(1);
  }
  if (!lastSetAuthJwt) {
    console.error("FAILED: Expected set-auth-jwt header on getSession() response, got none!");
    process.exit(1);
  }
  console.log("Captured set-auth-jwt header from getSession:", lastSetAuthJwt);

  // Verify the JWT with jose
  const { payload: sessionJwtPayload } = await jwtVerify(lastSetAuthJwt, importedKey);
  console.log("Verified set-auth-jwt payload:", sessionJwtPayload);
  if (sessionJwtPayload.email !== email || sessionJwtPayload.name !== name) {
    console.error("Claims mismatch in set-auth-jwt:", sessionJwtPayload);
    process.exit(1);
  }

  // 4. Test client.$fetch("/token")
  console.log("\n[4] Testing client.$fetch('/token')...");
  const tokenRes = await client.$fetch("/token", { method: "GET" });
  if (tokenRes.error || !tokenRes.data?.token) {
    console.error("GET /token failed:", tokenRes.error || tokenRes.data);
    process.exit(1);
  }
  console.log("Received token from /token:", tokenRes.data.token);
  const { payload: tokenPayload } = await jwtVerify(tokenRes.data.token, importedKey);
  console.log("Verified /token payload with jose:", tokenPayload);
  if (tokenPayload.email !== email) {
    console.error("Email mismatch in /token JWT:", tokenPayload);
    process.exit(1);
  }

  // 5. /sign-jwt and /verify-jwt are SERVER_ONLY in better-auth (auth.api.signJWT / verifyJWT):
  // they must not be reachable over HTTP, otherwise anyone could mint a JWT for any subject.
  console.log("\n[5] Checking /sign-jwt and /verify-jwt are not exposed over HTTP...");
  for (const [path, body] of [
    ["/sign-jwt", { payload: { sub: "custom-subject-456", role: "superadmin" } }],
    ["/verify-jwt", { token: tokenRes.data.token }],
  ]) {
    const res = await client.$fetch(path, { method: "POST", body });
    if (res.error?.status !== 404) {
      console.error(`POST ${path} should be 404 (server-only), got:`, res.error || res.data);
      process.exit(1);
    }
    console.log(`POST ${path} -> 404 (server-only)`);
  }

  console.log("\n✅ All official better-auth/client JWT plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
