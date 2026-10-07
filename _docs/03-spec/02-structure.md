# 02 – Target structure

## Layout

```
goauth/
├── goauth.go / goauth.options.go     # SetupGoAuth(api, opts): wires everything below
└── src/
    ├── config/                       # better-auth shaped options + GoAuth extension structs (04-config.md)
    ├── models/                       # better-auth compatible GORM models; goauth extras at the bottom
    ├── app/
    │   ├── repository/
    │   │   ├── repo_interfaces/      # IUserRepo, ISessionRepo, IAccountRepo, IVerificationRepo, ITxManager
    │   │   └── gormauth/             # default GORM implementation (+ migrator); others can be plugged in
    │   ├── services/
    │   │   ├── serv_interfaces/      # service contracts used by adapters and plugins
    │   │   ├── auth/                 # better-auth behaviour: sign-up/in/out, password, email, account, user
    │   │   ├── session/              # session manager (from src/sessions): create/get/refresh/revoke/list
    │   │   └── token/                # goauth JWT access/refresh issued on top of sessions
    │   ├── adapters/
    │   │   └── huma/                 # better-auth endpoints + session middlewares (from src/app/core/ba)
    │   └── core/                     # legacy goauth routes – untouched, later thin wrappers over services/*
    ├── providers/
    │   ├── authcrypto/   ✅          # scrypt/bcrypt/argon2, XChaCha20 envelopes, HS256 JWT
    │   ├── cookies/      ✅          # cookie names/attributes, HMAC signing, reading
    │   ├── idgen/        ✅          # ULID, 32-char random IDs and tokens
    │   ├── sec-storage/              # secondary storage (memory, redis)
    │   ├── hasher/                   # (folds into authcrypto)
    │   └── token/                    # legacy JWT helpers (folds into services/token)
    ├── plugins/
    │   ├── admin/                    # same layering: models, repository, services, adapters
    │   └── org/
    └── common/                       # errors (+ better-auth error catalogue), types, middleware, utils
```

## Dependency rule

```
adapters ──▶ services ──▶ repo_interfaces ◀── gormauth (or any other implementation)
    │            │
    └────────────┴──▶ providers, config, models, common
```

- Services never import Huma or GORM.
- Adapters never touch repositories directly.
- Plugins get services, repositories and providers through `plugins.InitContext`.

## What moves where

| Today | Target | Step |
|---|---|---|
| `src/authcrypto`, `compat/{cookies,signedcookie,id}.go` | `src/providers/{authcrypto,cookies,idgen}` | ✅ 0 |
| `compat/errors.go`, `compat/apierror.go` | `src/common/errors` (one error type: `{code,message}` + status) | 4 |
| `compat/dto.go` | deleted – models marshal to better-auth JSON themselves | 4 |
| `src/sessions` | `src/app/services/session` (manager) + `src/app/adapters/huma` (middlewares) | 4 |
| `src/app/core/ba` | `src/app/adapters/huma` | 6 |
| `src/providers/hasher` | `src/providers/authcrypto` (`TokenHash`, `TokenMatches`) | 4 |
| `src/app/core/*` legacy services | rewired onto `services/*` (no route changes) | 7 |
| `compat/` package | removed | 6 |

## Mode switch

`Mode` stays until the end of the migration:

- `ModeLegacy`: legacy routes only (today's behaviour).
- `ModeCompat`: legacy routes **and** better-auth endpoints, sharing services and database.

Once the legacy routes are thin wrappers (step 7), `Mode` can be replaced by two flags:
`LegacyRoutes` and `BetterAuthRoutes`.
