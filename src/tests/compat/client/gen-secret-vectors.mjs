// Generates src/providers/authcrypto/testdata/better_auth_rotation_vectors.json with the installed better-auth:
// data a TypeScript better-auth server writes with `secrets` (secret rotation), so the Go tests can prove goauth
// reads it. Run from this directory: `node gen-secret-vectors.mjs`.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { symmetricEncrypt, symmetricEncodeJWT, makeSignature, signJWT } from "better-auth/crypto";
import { createHMAC } from "@better-auth/utils/hmac";
import { base64Url } from "@better-auth/utils/base64";

const legacy = "legacy-secret-0000000000000000000000000000";
const v1 = "rotation-secret-v1-1111111111111111111111111";
const v2 = "rotation-secret-v2-2222222222222222222222222";

// better-auth's buildSecretConfig: the first entry is current, the legacy secret decrypts bare hex.
const configV2 = { keys: new Map([[2, v2], [1, v1]]), currentVersion: 2, legacySecret: legacy };
const configV1 = { keys: new Map([[1, v1]]), currentVersion: 1, legacySecret: legacy };

const plaintext = "otpauth-secret-JBSWY3DPEHPK3PXP <&> ü";
const tenYears = 10 * 365 * 24 * 60 * 60;

const sessionData = {
	session: {
		id: "sess_1",
		token: "tok_1",
		userId: "user_1",
		expiresAt: "2099-01-01T00:00:00.000Z",
		createdAt: "2024-01-01T00:00:00.000Z",
		updatedAt: "2024-01-01T00:00:00.000Z",
		ipAddress: "127.0.0.1",
		userAgent: "node <test> & co",
	},
	user: {
		id: "user_1",
		email: "a@example.com",
		name: "Ann <A&B>",
		emailVerified: true,
		image: null,
		createdAt: "2024-01-01T00:00:00.000Z",
		updatedAt: "2024-01-01T00:00:00.000Z",
	},
	updatedAt: 1700000000000,
	version: "1",
};

// compact cookie cache exactly as setCookieCache builds it (signed with ctx.context.secret = current secret)
async function compactCache(secret) {
	const expiresAt = 4102444800000; // 2100-01-01
	const signature = await createHMAC("SHA-256", "base64urlnopad").sign(secret, JSON.stringify({ ...sessionData, expiresAt }));
	return base64Url.encode(JSON.stringify({ session: sessionData, expiresAt, signature }), { padding: false });
}

const account = {
	id: "acc_1",
	accountId: "gh_1",
	providerId: "github",
	userId: "user_1",
	accessToken: "gho_access",
	refreshToken: "ghr_refresh",
	idToken: null,
	scope: "read:user,user:email",
	createdAt: "2024-01-01T00:00:00.000Z",
	updatedAt: "2024-01-01T00:00:00.000Z",
};

const out = {
	legacySecret: legacy,
	secretV1: v1,
	secretV2: v2,
	plaintext,
	envelopeV2: await symmetricEncrypt({ key: configV2, data: plaintext }),
	envelopeV1: await symmetricEncrypt({ key: configV1, data: plaintext }),
	bareHexLegacy: await symmetricEncrypt({ key: legacy, data: plaintext }),
	sessionData,
	jweSessionV2: await symmetricEncodeJWT(sessionData, configV2, "better-auth-session", tenYears),
	jweSessionV1: await symmetricEncodeJWT(sessionData, configV1, "better-auth-session", tenYears),
	jweSessionLegacy: await symmetricEncodeJWT(sessionData, legacy, "better-auth-session", tenYears),
	jweExpired: await symmetricEncodeJWT(sessionData, configV2, "better-auth-session", -60),
	account,
	jweAccountV2: await symmetricEncodeJWT(account, configV2, "better-auth-account", tenYears),
	jwtSessionV2: await signJWT(sessionData, v2, tenYears),
	compactSessionV2: await compactCache(v2),
	signedCookieV1: `tok_1.${await makeSignature("tok_1", v1)}`,
	signedCookieV2: `tok_1.${await makeSignature("tok_1", v2)}`,
};

const target = join(dirname(fileURLToPath(import.meta.url)), "../../../providers/authcrypto/testdata/better_auth_rotation_vectors.json");
writeFileSync(target, JSON.stringify(out, null, 2) + "\n");
console.log("wrote", target);
