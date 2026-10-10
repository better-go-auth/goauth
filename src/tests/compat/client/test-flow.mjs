import { createAuthClient } from "better-auth/client";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
console.log("Running official better-auth/client test against:", baseURL);

// Cookie jar for Node.js environment
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
      if (str.includes("Max-Age=0") || str.includes("expires=Thu, 01 Jan 1970")) {
        cookies.delete(name);
      } else {
        cookies.set(name, value);
      }
    }
  }
}

const client = createAuthClient({
  baseURL,
  fetchOptions: {
    onRequest(ctx) {
      ctx.headers.set("origin", baseURL);
      const c = getCookieHeader();
      if (c) {
        ctx.headers.set("cookie", c);
      }
    },
    onResponse(ctx) {
      saveCookies(ctx.response);
    },
  },
});

async function main() {
  const ts = Date.now();
  const email = `official-client-${ts}@example.com`;
  const password = "Password123!";
  const name = "Ada Lovelace";

  console.log("\n[1] Testing client.signUp.email...");
  const signUpRes = await client.signUp.email({
    email,
    password,
    name,
  });

  if (signUpRes.error) {
    console.error("signUp.email failed:", signUpRes.error);
    process.exit(1);
  }
  console.log("signUp result:", JSON.stringify(signUpRes.data, null, 2));
  if (!signUpRes.data?.user || signUpRes.data.user.email !== email) {
    console.error("signUp user mismatch:", signUpRes.data);
    process.exit(1);
  }

  console.log("\n[2] Testing client.getSession() with auto sign-in session...");
  const getSessionRes1 = await client.getSession();
  if (getSessionRes1.error) {
    console.error("getSession failed:", getSessionRes1.error);
    process.exit(1);
  }
  console.log("getSession data:", JSON.stringify(getSessionRes1.data, null, 2));
  if (!getSessionRes1.data?.session || !getSessionRes1.data?.user) {
    console.error("Expected session and user from getSession, got:", getSessionRes1.data);
    process.exit(1);
  }
  if (getSessionRes1.data.user.email !== email) {
    console.error("User email mismatch in session:", getSessionRes1.data.user.email);
    process.exit(1);
  }

  console.log("\n[3] Testing client.signOut()...");
  const signOutRes = await client.signOut();
  if (signOutRes.error) {
    console.error("signOut failed:", signOutRes.error);
    process.exit(1);
  }
  console.log("signOut success:", signOutRes.data);

  console.log("\n[4] Testing client.getSession() after signOut (should be null)...");
  const getSessionRes2 = await client.getSession();
  if (getSessionRes2.data !== null && getSessionRes2.data !== undefined) {
    console.error("Expected null session after sign-out, got:", getSessionRes2.data);
    process.exit(1);
  }
  console.log("Session cleared verified: null");

  console.log("\n[5] Testing client.signIn.email...");
  const signInRes = await client.signIn.email({
    email,
    password,
  });
  if (signInRes.error) {
    console.error("signIn.email failed:", signInRes.error);
    process.exit(1);
  }
  console.log("signIn result:", JSON.stringify(signInRes.data, null, 2));
  if (!signInRes.data?.user || signInRes.data.user.email !== email) {
    console.error("signIn user mismatch:", signInRes.data);
    process.exit(1);
  }

  console.log("\n[6] Testing client.getSession() after signIn...");
  const getSessionRes3 = await client.getSession();
  if (!getSessionRes3.data?.session || !getSessionRes3.data?.user) {
    console.error("Expected session after signIn, got:", getSessionRes3.data);
    process.exit(1);
  }
  console.log("Post-signIn session verified for:", getSessionRes3.data.user.email);

  console.log("\n✅ All official better-auth/client tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
