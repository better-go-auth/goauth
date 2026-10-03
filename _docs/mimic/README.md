# goauth → better-auth compatibility plan ("mimic")

Goal: make **goauth** feature-complete and **wire-compatible** with
**better-auth** (TypeScript), using **better-go-auth** as a reference
implementation and a source of portable code.

"Compatible" means, in priority order:

1. **HTTP wire compatibility** – the official `better-auth/client` (and
   `@better-auth/expo`, plugin clients) can talk to a goauth server unchanged:
   same paths, methods, request bodies, response bodies, status codes, error
   shape, cookies and headers.
2. **Token/cookie compatibility** – a session cookie or bearer token minted by
   better-auth is accepted by goauth and vice-versa (same secret).
3. **Database compatibility** – goauth can run against a database created by
   better-auth (same tables/columns) and vice-versa, including password hashes.
4. **Option/feature parity** – every better-auth option and official plugin has
   a goauth equivalent.

## Documents

| File | Content |
|---|---|
| [01-comparison.md](01-comparison.md) | Side-by-side comparison of goauth, better-go-auth and better-auth |
| [02-gap-analysis.md](02-gap-analysis.md) | What goauth is missing / does differently, with severity |
| [03-roadmap.md](03-roadmap.md) | Concrete, ordered steps (easy → hard) with acceptance criteria |
| [04-wire-contract.md](04-wire-contract.md) | The target contract: endpoints, payloads, cookies, hashing, schema |
| [05-plugins.md](05-plugins.md) | Plugin-by-plugin parity plan, ordered by effort |
| [06-compat-testing.md](06-compat-testing.md) | How to prove compatibility (golden tests, cross-server tests) |

## Guiding principles

- **Two modes during migration.** Add `Mode: goauth.ModeLegacy | goauth.ModeCompat`.
  Legacy keeps today's JWT access/refresh routes (`/signup`, `/login`, …);
  Compat exposes better-auth routes. Default flips to Compat at v2.
- **Port, don't re-invent.** better-go-auth already contains tested,
  wire-compatible code for signed cookies, cookie cache (compact/jwt/jwe),
  email-verification JWTs, secondary storage and OAuth. Port these packages.
- **better-auth source is the spec.** When docs disagree, read
  `better-auth/packages/better-auth/src/api/routes/*.ts` and
  `better-auth/packages/core/src`. Record every decision in `04-wire-contract.md`.
- **Keep goauth strengths as extensions**: Huma/OpenAPI-first routing,
  operation-ID RBAC, typed hook registry, org approval/blocking, push
  `deviceToken`. They must live outside the better-auth path namespace or be
  opt-in, never change compat responses.
- **Every step ships with a test** that compares against better-auth behaviour
  (see `06-compat-testing.md`).
