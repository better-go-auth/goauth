import { createAuthClient } from "better-auth/client";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
console.log("Running official better-auth/client Bearer test against:", baseURL);

let currentBearerToken = "";

// Notice: NO COOKIES! We specifically do NOT store or send cookies.
// All session state relies purely on the Bearer token in Authorization header.
const client = createAuthClient({
  baseURL,
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
    },
    onResponse(ctx) {
      const authToken = ctx.response.headers.get("set-auth-token");
      if (authToken) {
        currentBearerToken = authToken;
      }
    },
  },
});

async function main() {
  const ts = Date.now();
  const email = `bearer-client-${ts}@example.com`;
  const password = "Password123!";
  const name = "Bearer Token User";

  console.log("\n[1] Testing client.signUp.email with Bearer token capture...");
  const signUpRes = await client.signUp.email({
    email,
    password,
    name,
  });

  if (signUpRes.error) {
    console.error("signUp.email failed:", signUpRes.error);
    process.exit(1);
  }
  console.log("signUp completed successfully, user:", signUpRes.data?.user?.email);
  if (!currentBearerToken) {
    console.error("FAILED: No set-auth-token captured after signUp!");
    process.exit(1);
  }
  console.log("Captured Bearer token from set-auth-token:", currentBearerToken);

  console.log("\n[2] Testing client.getSession() with Bearer token (no cookies)...");
  const getSessionRes1 = await client.getSession();
  if (getSessionRes1.error) {
    console.error("getSession failed:", getSessionRes1.error);
    process.exit(1);
  }
  console.log("getSession data:", JSON.stringify(getSessionRes1.data, null, 2));
  if (!getSessionRes1.data?.session || !getSessionRes1.data?.user) {
    console.error("Expected session and user from getSession via Bearer, got:", getSessionRes1.data);
    process.exit(1);
  }
  if (getSessionRes1.data.user.email !== email) {
    console.error("User email mismatch in Bearer session:", getSessionRes1.data.user.email);
    process.exit(1);
  }

  console.log("\n[3] Testing client.signOut() with Bearer token...");
  const signOutRes = await client.signOut();
  if (signOutRes.error) {
    console.error("signOut failed:", signOutRes.error);
    process.exit(1);
  }
  console.log("signOut success:", signOutRes.data);

  // Clear current bearer token on client
  const prevToken = currentBearerToken;
  currentBearerToken = "";

  console.log("\n[4] Testing client.getSession() after signOut (should be null)...");
  const getSessionRes2 = await client.getSession();
  if (getSessionRes2.data !== null && getSessionRes2.data !== undefined) {
    console.error("Expected null session after sign-out, got:", getSessionRes2.data);
    process.exit(1);
  }
  console.log("Session cleared verified: null");

  console.log("\n[5] Testing client.getSession() with revoked token (should be null)...");
  currentBearerToken = prevToken;
  const getSessionRevoked = await client.getSession();
  if (getSessionRevoked.data !== null && getSessionRevoked.data !== undefined) {
    console.error("Expected revoked session to return null, got:", getSessionRevoked.data);
    process.exit(1);
  }
  console.log("Revoked token rejected successfully!");
  currentBearerToken = "";

  console.log("\n[6] Testing client.signIn.email...");
  const signInRes = await client.signIn.email({
    email,
    password,
  });
  if (signInRes.error) {
    console.error("signIn.email failed:", signInRes.error);
    process.exit(1);
  }
  if (!currentBearerToken) {
    console.error("FAILED: No set-auth-token captured after signIn!");
    process.exit(1);
  }
  console.log("Captured new Bearer token after signIn:", currentBearerToken);

  console.log("\n[7] Testing client.getSession() after signIn via Bearer...");
  const getSessionRes3 = await client.getSession();
  if (!getSessionRes3.data?.session || !getSessionRes3.data?.user) {
    console.error("Expected session after signIn via Bearer, got:", getSessionRes3.data);
    process.exit(1);
  }
  if (getSessionRes3.data.user.email !== email) {
    console.error("Session email mismatch:", getSessionRes3.data.user.email);
    process.exit(1);
  }
  console.log("Post-signIn Bearer session verified for:", getSessionRes3.data.user.email);

  console.log("\n✅ All official better-auth/client Bearer tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
