// Drives goauth's passkey plugin with the official better-auth client (better-auth 1.6.16 +
// @better-auth/passkey/client). Node has no WebAuthn, so a software authenticator (ES256, "none"
// attestation, hand-written CBOR) is installed as navigator.credentials for @simplewebauthn/browser.
import crypto from "node:crypto";
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
// The page origin the "browser" runs on; the server is configured with BaseURL = this origin (rpID "localhost").
const pageOrigin = process.env.PASSKEY_ORIGIN || "http://localhost:3000";
console.log("Running official @better-auth/passkey client test against:", baseURL, "origin:", pageOrigin);

function fail(msg, extra) {
  console.error("FAILED:", msg, extra ?? "");
  process.exit(1);
}

// ─── Minimal CBOR encoder (major types 0-5) ──────────────────────────────────

function cborHead(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

function cbor(v) {
  if (typeof v === "number") return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (typeof v === "string") {
    const s = Buffer.from(v, "utf8");
    return Buffer.concat([cborHead(3, s.length), s]);
  }
  if (v instanceof Uint8Array) return Buffer.concat([cborHead(2, v.length), Buffer.from(v)]);
  if (Array.isArray(v)) return Buffer.concat([cborHead(4, v.length), ...v.map(cbor)]);
  if (v instanceof Map) {
    const parts = [cborHead(5, v.size)];
    for (const [k, val] of v) parts.push(cbor(k), cbor(val));
    return Buffer.concat(parts);
  }
  throw new Error("cbor: unsupported value " + v);
}

// ─── Software authenticator ──────────────────────────────────────────────────

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const toArrayBuffer = (buf) => {
  const b = Buffer.from(buf);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
};
const AAGUID = Buffer.from("adce000235bcc60a648b0b25f1f05503", "hex");

class SoftAuthenticator {
  constructor() {
    this.credentials = []; // { id: Buffer, privateKey, publicJwk, rpId, userHandle, counter }
  }

  authData(rpId, counter, attested) {
    const rpIdHash = crypto.createHash("sha256").update(rpId).digest();
    // UP | UV (| AT)
    const flags = Buffer.from([0x01 | 0x04 | (attested ? 0x40 : 0)]);
    const ctr = Buffer.alloc(4);
    ctr.writeUInt32BE(counter);
    const parts = [rpIdHash, flags, ctr];
    if (attested) {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(attested.id.length);
      const x = Buffer.from(attested.publicJwk.x, "base64url");
      const y = Buffer.from(attested.publicJwk.y, "base64url");
      // COSE_Key: kty EC2 (1:2), alg ES256 (3:-7), crv P-256 (-1:1), x (-2), y (-3)
      const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
      parts.push(AAGUID, len, attested.id, cose);
    }
    return Buffer.concat(parts);
  }

  clientData(type, challenge) {
    return Buffer.from(JSON.stringify({ type, challenge: b64url(challenge), origin: pageOrigin, crossOrigin: false }));
  }

  async create({ publicKey }) {
    const rpId = publicKey.rp.id || "localhost";
    // excludeCredentials: refuse to register twice (browsers raise InvalidStateError)
    for (const ex of publicKey.excludeCredentials || []) {
      const exId = Buffer.from(ex.id);
      if (this.credentials.some((c) => c.id.equals(exId))) {
        throw new DOMException("The authenticator was previously registered", "InvalidStateError");
      }
    }
    if (!publicKey.pubKeyCredParams.some((p) => p.alg === -7)) {
      throw new DOMException("No supported algorithm", "NotSupportedError");
    }
    const { privateKey, publicKey: pub } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const cred = {
      id: crypto.randomBytes(16),
      privateKey,
      publicJwk: pub.export({ format: "jwk" }),
      rpId,
      userHandle: Buffer.from(publicKey.user.id),
      counter: 0,
    };
    this.credentials.push(cred);
    const authData = this.authData(rpId, cred.counter, cred);
    const attestationObject = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    const clientDataJSON = this.clientData("webauthn.create", publicKey.challenge);
    return {
      id: b64url(cred.id),
      rawId: toArrayBuffer(cred.id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: toArrayBuffer(clientDataJSON),
        attestationObject: toArrayBuffer(attestationObject),
        getTransports: () => ["internal", "hybrid"],
        getAuthenticatorData: () => toArrayBuffer(authData),
        getPublicKeyAlgorithm: () => -7,
        getPublicKey: () => null,
      },
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };
  }

  async get({ publicKey }) {
    const rpId = publicKey.rpId || "localhost";
    // allowCredentials narrows the choice; without it the discoverable credential for the RP is used
    let candidates = this.credentials.filter((c) => c.rpId === rpId);
    if (publicKey.allowCredentials && publicKey.allowCredentials.length) {
      const allowed = publicKey.allowCredentials.map((d) => Buffer.from(d.id));
      candidates = candidates.filter((c) => allowed.some((a) => a.equals(c.id)));
    }
    const cred = candidates[candidates.length - 1];
    if (!cred) throw new DOMException("No credential available", "NotAllowedError");
    cred.counter += 1;
    const authData = this.authData(rpId, cred.counter, null);
    const clientDataJSON = this.clientData("webauthn.get", publicKey.challenge);
    const signed = Buffer.concat([authData, crypto.createHash("sha256").update(clientDataJSON).digest()]);
    const signature = crypto.sign("sha256", signed, { key: cred.privateKey, dsaEncoding: "der" });
    return {
      id: b64url(cred.id),
      rawId: toArrayBuffer(cred.id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: toArrayBuffer(clientDataJSON),
        authenticatorData: toArrayBuffer(authData),
        signature: toArrayBuffer(signature),
        userHandle: toArrayBuffer(cred.userHandle),
      },
      getClientExtensionResults: () => ({}),
    };
  }
}

const authenticator = new SoftAuthenticator();
// Install the WebAuthn surface @simplewebauthn/browser feature-detects and calls.
globalThis.PublicKeyCredential = class PublicKeyCredential {
  static async isUserVerifyingPlatformAuthenticatorAvailable() {
    return true;
  }
  static async isConditionalMediationAvailable() {
    return false;
  }
};
globalThis.window = globalThis.window || globalThis;
const credentials = { create: (o) => authenticator.create(o), get: (o) => authenticator.get(o) };
try {
  Object.defineProperty(globalThis.navigator, "credentials", { value: credentials, configurable: true });
} catch {
  Object.defineProperty(globalThis, "navigator", { value: { credentials }, configurable: true });
}

// ─── Client with a cookie jar ────────────────────────────────────────────────

const cookies = new Map();
function cookieHeader() {
  return Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
}
function saveCookies(response) {
  for (const str of response.headers.getSetCookie?.() || []) {
    const [pair] = str.split(";");
    const idx = pair.indexOf("=");
    const name = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (/Max-Age=0|Max-Age=-|expires=Thu, 01 Jan 1970/i.test(str) || value === "") cookies.delete(name);
    else cookies.set(name, value);
  }
}

const client = createAuthClient({
  baseURL,
  plugins: [passkeyClient()],
  fetchOptions: {
    onRequest(ctx) {
      ctx.headers.set("origin", pageOrigin);
      const c = cookieHeader();
      if (c) ctx.headers.set("cookie", c);
    },
    onResponse(ctx) {
      saveCookies(ctx.response);
    },
  },
});

async function main() {
  const email = `passkey-client-${Date.now()}@example.com`;

  console.log("\n[1] signUp.email");
  const up = await client.signUp.email({ email, password: "Password123!", name: "Passkey User" });
  if (up.error) fail("signUp.email", up.error);
  const userId = up.data.user.id;

  console.log("\n[2] passkey.addPasskey");
  const added = await client.passkey.addPasskey({ name: "node-key" });
  if (added.error) fail("addPasskey", added.error);
  const pk = added.data;
  if (pk.name !== "node-key" || pk.userId !== userId || pk.deviceType !== "singleDevice" || pk.transports !== "internal,hybrid") {
    fail("unexpected passkey", pk);
  }
  if (pk.aaguid !== "adce0002-35bc-c60a-648b-0b25f1f05503" || pk.counter !== 0 || !pk.publicKey || !pk.credentialID) {
    fail("unexpected passkey fields", pk);
  }
  if (!cookies.has("better-auth.better-auth-passkey")) fail("challenge cookie not set");
  console.log("registered passkey:", pk.id);

  console.log("\n[3] addPasskey again (excludeCredentials)");
  const again = await client.passkey.addPasskey({ name: "dup" });
  if (!again.error || again.error.code !== "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED") fail("expected previously registered", again);

  console.log("\n[4] passkey.listUserPasskeys");
  const list = await client.passkey.listUserPasskeys();
  if (list.error) fail("listUserPasskeys", list.error);
  if (!Array.isArray(list.data) || list.data.length !== 1 || list.data[0].id !== pk.id) fail("unexpected list", list.data);

  console.log("\n[5] signOut");
  const out = await client.signOut();
  if (out.error) fail("signOut", out.error);
  const gone = await client.getSession();
  if (gone.data) fail("session still present after sign-out", gone.data);

  console.log("\n[6] signIn.passkey");
  const signIn = await client.signIn.passkey();
  if (signIn.error) fail("signIn.passkey", signIn.error);
  if (signIn.data?.user?.id !== userId || !signIn.data?.session?.token) fail("unexpected sign-in response", signIn.data);

  console.log("\n[7] getSession after passkey sign-in");
  const sess = await client.getSession();
  if (sess.error || sess.data?.user?.email !== email) fail("getSession", sess);

  console.log("\n[8] counter persisted");
  const list2 = await client.passkey.listUserPasskeys();
  if (list2.data?.[0]?.counter !== 1) fail("counter not updated", list2.data);

  console.log("\n[9] passkey.updatePasskey");
  const upd = await client.passkey.updatePasskey({ id: pk.id, name: "renamed-key" });
  if (upd.error || upd.data?.passkey?.name !== "renamed-key") fail("updatePasskey", upd);

  console.log("\n[10] updatePasskey with unknown id");
  const bad = await client.passkey.updatePasskey({ id: "does-not-exist", name: "x" });
  if (!bad.error || bad.error.status !== 404 || bad.error.code !== "PASSKEY_NOT_FOUND") fail("expected 404 PASSKEY_NOT_FOUND", bad.error);

  console.log("\n[11] passkey.deletePasskey");
  const del = await client.passkey.deletePasskey({ id: pk.id });
  if (del.error || del.data?.status !== true) fail("deletePasskey", del);
  const list3 = await client.passkey.listUserPasskeys();
  if (list3.data?.length !== 0) fail("passkey still listed", list3.data);

  console.log("\n[12] signIn.passkey with the deleted passkey");
  await client.signOut();
  const denied = await client.signIn.passkey();
  if (!denied.error || denied.error.status !== 401 || denied.error.code !== "PASSKEY_NOT_FOUND") fail("expected 401 PASSKEY_NOT_FOUND", denied.error);

  console.log("\nAll passkey client checks passed.");
}

main().catch((e) => fail("unhandled", e));
