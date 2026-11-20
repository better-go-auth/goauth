// Prints @better-auth/api-key's API_KEY_ERROR_CODES as {code: message} JSON and test vectors of its
// defaultKeyHasher, for src/tests/compat/apikeyclient to compare with goauth's port.
import { API_KEY_ERROR_CODES, defaultKeyHasher } from "@better-auth/api-key";

const codes = Object.fromEntries(Object.entries(API_KEY_ERROR_CODES).map(([k, v]) => [k, typeof v === "string" ? v : v.message]));
const hashes = {};
for (const key of ["test-key", "goauth_AbCdEfGhIjKlMnOp", "x".repeat(64)]) hashes[key] = await defaultKeyHasher(key);
console.log(JSON.stringify({ codes, hashes }));
