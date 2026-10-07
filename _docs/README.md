# goauth docs

Goal: make goauth's database and HTTP API compatible with **better-auth** (TypeScript), using
**better-go-auth** as a reference, while keeping goauth's extras (legacy JWT access/refresh tokens,
swappable repositories, org/admin plugins).

## Where things are

Folders are numbered in the order the work happened. Files inside are numbered in reading order.

| Folder | Content | Keep up to date? |
|---|---|---|
| [01-architecture-ideas](01-architecture-ideas) | Early design suggestions (plugin lifecycle, hooks, DB/adapter independence). Each has a status table. | Status tables only |
| [02-research](02-research) | How goauth, better-go-auth and better-auth compare; gaps; how sessions/cookies work in each. Snapshot of the code at the time. | No |
| [03-spec](03-spec) | The target: wire contract, folder structure, schema, config, plugins, compat testing, phone/no-email users. | Yes, when a decision changes |
| [04-plan](04-plan) | **[02-steps.md](04-plan/02-steps.md) is the active plan** (status, next up, breaking checklist). `01` is the older compat-layer roadmap, kept for the detail of later phases. `03+` are finished sub-plans. | Yes, after every step |
| [05-notes](05-notes) | Open questions and small todos. | Yes |

## Adding a document

- New explanation of how something works today → `02-research/NN-topic.md`.
- New target behaviour or design decision → `03-spec/NN-topic.md`.
- New piece of work → a step in `04-plan/02-steps.md`; if it needs its own plan, `04-plan/NN-topic.md`,
  renamed to `NN-done-topic.md` when finished.
- A question → `05-notes/01-open-questions.md`.

Use the next free number. Don't renumber existing files; links depend on them.

## Goals

1. **Database compatible with better-auth first.** Same tables, columns and meaning. snake_case columns
   for now; camelCase is an optional later step.
2. **More features on top, never instead of:**
   - goauth's access/refresh JWT flow keeps working on the same session table and services;
   - goauth-only columns sit at the bottom of each model;
   - goauth-only options live in a `GoAuth` sub-struct of each config section, everything else mirrors better-auth.
3. **Plugins in scope now:** admin and organization. The JWT/JWKS plugin comes later.
4. **Structure like better-go-auth:** swappable repositories, framework adapters, framework-agnostic services,
   pluggable providers.
5. Breaking changes are acceptable; existing databases don't need to be preserved.

"Compatible" means, in priority order:

1. **HTTP:** the official `better-auth/client` (and `@better-auth/expo`, plugin clients) works unchanged:
   same paths, bodies, status codes, error shape, cookies and headers.
2. **Tokens and cookies:** a session cookie minted by one server is accepted by the other (same secret).
3. **Database:** goauth runs on a database created by better-auth and vice versa, including password hashes.
4. **Features:** every better-auth option and official plugin has a goauth equivalent.

## Principles

- **better-auth's source is the spec.** When docs disagree, read
  `better-auth/packages/better-auth/src/api/routes/*.ts` and `better-auth/packages/core/src`, and record the
  decision in `03-spec`.
- **Port, don't reinvent.** better-go-auth has tested code for signed cookies, cookie cache,
  email-verification JWTs, secondary storage and OAuth.
- **Keep goauth's strengths as extensions:** Huma/OpenAPI-first routing, operation-ID RBAC, typed hooks,
  org approval/blocking. They must never change better-auth responses.
- **Every step ships with a test** against better-auth behaviour (see [03-spec/06-compat-testing.md](03-spec/06-compat-testing.md)).
