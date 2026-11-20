import { createAuthClient } from "better-auth/client";
import { siweClient } from "better-auth/client/plugins";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { randomBytes } from "node:crypto";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
// the Go runner configures BaseURL http://localhost:3000, so messages are issued for localhost:3000
const domain = "localhost:3000";

console.log("Running official better-auth/client siwe test against:", baseURL);

// ─── A minimal secp256k1 wallet (BigInt; @noble/curves is not installed) ──────

const P = 2n ** 256n - 2n ** 32n - 977n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
];

const mod = (a, m) => ((a % m) + m) % m;

function inv(a, m) {
  let [lm, hm, low, high] = [1n, 0n, mod(a, m), m];
  while (low > 1n) {
    const r = high / low;
    [lm, hm] = [hm - lm * r, lm];
    [low, high] = [high - low * r, low];
  }
  return mod(lm, m);
}

function add(p, q) {
  if (!p) return q;
  if (!q) return p;
  let l;
  if (p[0] === q[0]) {
    if (mod(p[1] + q[1], P) === 0n) return null;
    l = mod(3n * p[0] * p[0] * inv(2n * p[1], P), P);
  } else {
    l = mod((q[1] - p[1]) * inv(q[0] - p[0], P), P);
  }
  const x = mod(l * l - p[0] - q[0], P);
  return [x, mod(l * (p[0] - x) - p[1], P)];
}

function mul(k, pt) {
  let r = null;
  let a = pt;
  while (k > 0n) {
    if (k & 1n) r = add(r, a);
    a = add(a, a);
    k >>= 1n;
  }
  return r;
}

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const toBig = (bytes) => BigInt("0x" + hex(bytes));
const pad32 = (n) => n.toString(16).padStart(64, "0");

function randomScalar() {
  for (;;) {
    const k = toBig(randomBytes(32));
    if (k > 0n && k < N) return k;
  }
}

function checksum(addressHex) {
  const lower = addressHex.toLowerCase().replace(/^0x/, "");
  const hash = hex(keccak_256(new TextEncoder().encode(lower)));
  let out = "0x";
  for (let i = 0; i < 40; i++) out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  return out;
}

function makeWallet() {
  const d = randomScalar();
  const pub = mul(d, G);
  const pubBytes = Buffer.from(pad32(pub[0]) + pad32(pub[1]), "hex");
  return { d, address: checksum(hex(keccak_256(pubBytes)).slice(24)) };
}

// personalSign is EIP-191 personal_sign: r || s || v with low s and v = 27 / 28.
function personalSign(wallet, message) {
  const msg = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msg.length}`);
  const z = toBig(keccak_256(Buffer.concat([prefix, msg])));
  for (;;) {
    const k = randomScalar();
    const R = mul(k, G);
    const r = mod(R[0], N);
    if (r === 0n) continue;
    let s = mod(inv(k, N) * (z + r * wallet.d), N);
    if (s === 0n) continue;
    let recid = Number(R[1] & 1n);
    if (s > N / 2n) {
      s = N - s;
      recid ^= 1;
    }
    return "0x" + pad32(r) + pad32(s) + (27 + recid).toString(16);
  }
}

// siweMessage builds an EIP-4361 message like viem's createSiweMessage.
function siweMessage({ address, chainId, nonce, expirationTime, statement = "Sign in with Ethereum." }) {
  let m = `${domain} wants you to sign in with your Ethereum account:\n${address}\n\n${statement}\n\n`;
  m += `URI: http://${domain}\nVersion: 1\nChain ID: ${chainId}\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}`;
  if (expirationTime) m += `\nExpiration Time: ${expirationTime.toISOString()}`;
  return m;
}

// ─── Client ──────────────────────────────────────────────────────────────────

function makeClient(url) {
  const cookies = new Map();
  const cookieHeader = () => Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
  function saveCookies(response) {
    for (const str of response.headers.getSetCookie?.() || []) {
      const [pair] = str.split(";");
      const idx = pair.indexOf("=");
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      if (str.includes("Max-Age=0") || value === "") cookies.delete(name);
      else cookies.set(name, value);
    }
  }
  return createAuthClient({
    baseURL: url,
    plugins: [siweClient()],
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
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

function expectError(res, { code, message, status }, label) {
  assert(res.error, `${label}: expected an error, got data ${JSON.stringify(res.data)}`);
  if (code) assert(res.error.code === code, `${label}: expected code ${code}, got ${JSON.stringify(res.error)}`);
  if (message) assert(res.error.message === message, `${label}: expected message ${message}, got ${JSON.stringify(res.error)}`);
  if (status) assert(res.error.status === status, `${label}: expected status ${status}, got ${res.error.status}`);
}

async function signIn(client, wallet, chainId) {
  const n = await client.siwe.nonce({ walletAddress: wallet.address, chainId });
  assert(!n.error && typeof n.data.nonce === "string", `nonce: ${JSON.stringify(n)}`);
  const message = siweMessage({ address: wallet.address, chainId, nonce: n.data.nonce });
  return { message, res: await client.siwe.verify({ message, signature: personalSign(wallet, message), walletAddress: wallet.address, chainId }) };
}

async function main() {
  const wallet = makeWallet();
  const client = makeClient(baseURL);

  // 1. nonce → sign → verify signs the wallet in
  console.log("\n[1] siwe.nonce + siwe.verify...");
  const { message, res } = await signIn(client, wallet, 1);
  assert(!res.error, `verify failed: ${JSON.stringify(res.error)}`);
  assert(res.data.success === true && typeof res.data.token === "string" && res.data.user.walletAddress === wallet.address && res.data.user.chainId === 1,
    `verify data: ${JSON.stringify(res.data)}`);
  const userId = res.data.user.id;

  // 2. the session cookie works
  console.log("\n[2] getSession...");
  const sess = await client.getSession();
  assert(!sess.error && sess.data?.user?.id === userId && sess.data.user.name === wallet.address &&
    sess.data.user.email === `${wallet.address.toLowerCase()}@http://localhost:3000`, `getSession: ${JSON.stringify(sess)}`);

  // 3. the nonce is single use
  console.log("\n[3] nonce reuse...");
  const reuse = await client.siwe.verify({ message, signature: personalSign(wallet, message), walletAddress: wallet.address, chainId: 1 });
  expectError(reuse, { code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE", message: "Unauthorized: Invalid or expired nonce", status: 401 }, "nonce reuse");

  // 4. a signature by another key
  console.log("\n[4] wrong signature...");
  const n4 = await client.siwe.nonce({ walletAddress: wallet.address });
  const m4 = siweMessage({ address: wallet.address, chainId: 1, nonce: n4.data.nonce });
  const wrong = await client.siwe.verify({ message: m4, signature: personalSign(makeWallet(), m4), walletAddress: wallet.address });
  expectError(wrong, { message: "Unauthorized: Invalid SIWE signature", status: 401 }, "wrong signature");

  // 5. the message's chain differs from the request's
  console.log("\n[5] chain id mismatch...");
  const m5 = siweMessage({ address: wallet.address, chainId: 10, nonce: n4.data.nonce });
  const mismatch = await client.siwe.verify({ message: m5, signature: personalSign(wallet, m5), walletAddress: wallet.address, chainId: 1 });
  expectError(mismatch, { code: "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH", status: 401 }, "chain mismatch");

  // 6. an expired message
  console.log("\n[6] expired message...");
  const m6 = siweMessage({ address: wallet.address, chainId: 1, nonce: n4.data.nonce, expirationTime: new Date(Date.now() - 1000) });
  const expired = await client.siwe.verify({ message: m6, signature: personalSign(wallet, m6), walletAddress: wallet.address, chainId: 1 });
  expectError(expired, { code: "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED", status: 401 }, "expired message");

  // 7. the same address on another chain belongs to the same user (getNonce alias, address field)
  console.log("\n[7] second chain via siwe.getNonce...");
  const other = makeClient(baseURL);
  const n7 = await other.siwe.getNonce({ address: wallet.address.toLowerCase(), chainId: 137 });
  assert(!n7.error, `getNonce: ${JSON.stringify(n7.error)}`);
  const m7 = siweMessage({ address: wallet.address, chainId: 137, nonce: n7.data.nonce });
  const poly = await other.siwe.verify({ message: m7, signature: personalSign(wallet, m7), walletAddress: wallet.address, chainId: 137 });
  assert(!poly.error && poly.data.user.id === userId && poly.data.user.chainId === 137, `second chain: ${JSON.stringify(poly)}`);

  // 8. another wallet is another user
  console.log("\n[8] another wallet...");
  const { res: res8 } = await signIn(makeClient(baseURL), makeWallet(), 1);
  assert(!res8.error && res8.data.user.id !== userId, `another wallet: ${JSON.stringify(res8)}`);

  // 9. validation
  console.log("\n[9] validation...");
  const invalid = await client.siwe.nonce({ walletAddress: "0x1234" });
  expectError(invalid, { code: "VALIDATION_ERROR", status: 400 }, "invalid address");

  console.log("\n✅ All official better-auth/client siwe plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
