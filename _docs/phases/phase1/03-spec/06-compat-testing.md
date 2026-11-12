# 06 – Proving compatibility

Three layers of tests, cheapest first. All live under `goauth/src/tests/compat/`.

## 1. Vector tests (unit, no network)

Capture values from the TS reference server once, commit them as fixtures, assert in Go.

| Vector | How to capture (in `better-auth-schema/`) | Go assertion |
|---|---|---|
| scrypt hash | `await hashPassword("P@ssw0rd!")` via `better-auth/crypto` | `crypto.Verify(hash, pw) == true`; TS `verifyPassword` accepts Go hash |
| signed cookie | sign-in with `test-flow.ts`, record `Set-Cookie` | `signedcookie.Verify(value, secret)` returns token |
| cookie cache compact/jwt/jwe | run `server-cache-compact.ts`, `server-cache-jwt.ts`, `server-cache-jwe.ts` + `test-cookie-cache-payload.ts` | decode → same `session.id`, `user.email` |
| email verification JWT | capture token from `sendVerificationEmail` callback | `crypto.VerifyJWT(token, secret)` → `{email}` |
| symmetric encryption | `symmetricEncrypt({key: secret, data})` | Go decrypts; TS decrypts Go output |
| error catalogue | parse `packages/core/src/error/codes.ts` | every code/message exists in `compat/errors.go` |

Fixture file: `src/tests/compat/testdata/vectors.json` (secret fixed, e.g. 32 × `"a"`).

## 2. Golden HTTP tests (Go only)

- Start goauth (Compat mode, sqlite or testcontainers Postgres) on `httptest.Server`.
- For each endpoint in [01-wire-contract.md](01-wire-contract.md) §1, run the request and compare to
  `testdata/golden/<endpoint>.json` with volatile fields (`id`, `token`, dates) replaced by
  type placeholders (`"<string>"`, `"<date>"`).
- Golden files are produced by running the **same request script** against the TS server
  (`better-auth-schema/server.ts`) – see §4 – so goauth is diffed against real better-auth output.
- Also assert status codes, `Set-Cookie` names/attributes and the error body for each
  failure case (wrong password, duplicate email, short password, expired token, …).

## 3. Official client end-to-end (the real proof)

`goauth/src/tests/compat/client/` – a tiny Node project:

```ts
import { createAuthClient } from "better-auth/client";
import { usernameClient, adminClient, organizationClient } from "better-auth/client/plugins";
const client = createAuthClient({ baseURL: process.env.GOAUTH_URL, plugins: [/* enabled */] });
await client.signUp.email({ name: "A", email: "a@x.io", password: "password123" });
await client.signIn.email({ email: "a@x.io", password: "password123" });
const { data } = await client.getSession();
// …one script per roadmap phase / plugin
```

Run from Go test with `exec.Command("node", …)` behind build tag `compat_e2e`, or in CI as a
separate job. Also run `@better-auth/expo` flows for bearer/mobile once Phase 8 lands.

## 4. Cross-server / shared-database tests

Strongest guarantee for DB compatibility (Phase 2 onward):

1. `docker-compose` with Postgres + Redis.
2. TS server (`better-auth-schema/server.ts`) and goauth both point to the **same DB, same secret,
   same Redis** (goauth `Schema.Naming = NamingBetterAuth`).
3. Scenarios:
   - sign up on TS → sign in on goauth (password hash compat)
   - sign in on goauth → `get-session` on TS with the same cookie (cookie + session row compat)
   - sign in on TS with secondary storage → `get-session` on goauth (Redis key layout compat)
   - request password reset on goauth → complete on TS
   - `npx @better-auth/cli migrate` after goauth migration reports no pending changes

Reuse request collections already in the workspace:
`better-auth-schema/_docs/test/{bruno,hurl,postman.json}` and
`better-go-auth/tests/bruno/` – run them against both servers and diff responses.

## 5. Generating fixtures automatically

Add `better-auth-schema/scripts/capture-golden.ts`:
- boots `server.ts` with an in-memory/sqlite DB and a fixed secret,
- replays every request from a shared `requests.json`,
- writes normalised responses to `goauth/src/tests/compat/testdata/golden/`.

Re-run whenever better-auth is upgraded; a failing Go golden test then shows exactly which
part of the contract changed upstream.

## 6. CI gates

| Gate | Runs | Blocks merge |
|---|---|---|
| unit + vectors | every PR | yes |
| golden HTTP | every PR | yes |
| official client e2e | every PR touching `compat/`, `src/app/core/ba/`, `src/plugins/` | yes |
| cross-server shared DB | nightly + release | release only |
