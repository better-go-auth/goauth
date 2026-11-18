# Better Go Auth (`goauth`)

[![Go Reference](https://pkg.go.dev/badge/github.com/better-go-auth/goauth.svg)](https://pkg.go.dev/github.com/better-go-auth/goauth)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.24-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A high-performance, modular Go authentication framework engineered for native wire and database compatibility with [Better Auth](https://github.com/better-auth/better-auth) (TypeScript).

---

## Overview

**Better Go Auth (`goauth`)** provides an idiomatic, strongly-typed Go implementation of the Better Auth specification. It allows backend developers to power applications using the official TypeScript [`better-auth/client`](https://better-auth.com), `@better-auth/expo`, and frontend SDKs while running on a blazing-fast, compiled Go backend.

### Why `goauth`?

- **100% Better Auth Wire Compatibility**: Endpoints, JSON response shapes, status codes, and error structures (`{"code": "...", "message": "..."}`) match Better Auth exactly. Frontend clients work without changes.
- **Shared Session & Cookie Interoperability**: Compatible HMAC-signed session cookies and Argon2id password hashes allow seamless co-existence or migration between TypeScript and Go services sharing the same database and secret.
- **Framework-Agnostic Router Adapters**: Native support for standard `net/http` (`ServeMux`), `Chi`, `Gin`, and `Fiber v2`. Isolated subpackages ensure importing one router never pulls in dependencies for the others.
- **OpenAPI & Interactive Docs Built-In**: First-class OpenAPI 3.1 generation via Huma with zero-configuration documentation UIs (Stoplight Elements, Scalar, Swagger UI, RapiDoc).
- **Multi-Database & Multi-ORM Ready**: Production-tested across SQLite, PostgreSQL, and MySQL using GORM, with clean repository interfaces designed for Bun, sqlc, and `database/sql`.
- **Enterprise Plugin Ecosystem**: Built-in plugins for Organizations (multi-tenancy, teams, dynamic RBAC), Platform Administration, Opaque Bearer Tokens, JWT/JWKS, and Email OTP.

---

## Quickstart

### 1. Installation

```bash
go get github.com/better-go-auth/goauth
```

Install only the router adapter your project uses:

```bash
# For standard net/http (no external router dependencies):
go get github.com/better-go-auth/goauth/adapters/mux

# Or for Chi:
go get github.com/better-go-auth/goauth/adapters/chi

# Or for Gin:
go get github.com/better-go-auth/goauth/adapters/gin

# Or for Fiber v2:
go get github.com/better-go-auth/goauth/adapters/fiber
```

### 2. Basic Example (`net/http` ServeMux)

```go
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/adapters"
	muxadapter "github.com/better-go-auth/goauth/adapters/mux"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	// 1. Initialize Database
	db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// 2. Initialize Router & OpenAPI / Docs
	mux := http.NewServeMux()
	api := muxadapter.New(mux,
		adapters.WithTitle("My Auth API"),
		adapters.WithVersion("1.0.0"),
		adapters.WithScalarDocs("/docs"), // Interactive Scalar API documentation
	)

	// 3. Setup Better Go Auth
	_, err = goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		AuthConfig: config.AuthConfig{
			AppName:  "My Go App",
			BaseURL:  "http://localhost:8080",
			BasePath: "/api/auth",
			Secret:   "your-at-least-32-characters-long-secret-key!",
		},
		Conn: db,
		Plugins: []goauth.Plugin{
			bearer.New(bearerconfig.DefaultConfig()), // Opaque bearer token support
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize goauth: %v", err)
	}

	log.Println("Auth server running on :8080. Docs at http://localhost:8080/docs")
	http.ListenAndServe(":8080", mux)
}
```

---

## Router Adapters

Each router adapter lives in an isolated subpackage so your application only imports the framework it actually uses:

### Gin
```go
import (
	"github.com/better-go-auth/goauth/adapters"
	ginadapter "github.com/better-go-auth/goauth/adapters/gin"
	"github.com/gin-gonic/gin"
)

engine := gin.Default()
api := ginadapter.New(engine, adapters.WithScalarDocs("/docs"))
```

### Chi
```go
import (
	"github.com/better-go-auth/goauth/adapters"
	chiadapter "github.com/better-go-auth/goauth/adapters/chi"
	"github.com/go-chi/chi/v5"
)

router := chi.NewRouter()
api := chiadapter.New(router, adapters.WithSwaggerUIDocs("/docs"))
```

### Fiber v2
```go
import (
	"github.com/better-go-auth/goauth/adapters"
	fiberadapter "github.com/better-go-auth/goauth/adapters/fiber"
	"github.com/gofiber/fiber/v2"
)

app := fiber.New()
api := fiberadapter.New(app, adapters.WithDocs("/docs"))
```

---

## Interactive Documentation & OpenAPI

`goauth` integrates with Huma v2 to automatically generate OpenAPI 3.1 specifications (`/openapi.json` and `/openapi.yaml`) and interactive browser documentation:

- `adapters.WithStoplightDocs("/docs")`: Stoplight Elements UI (default).
- `adapters.WithScalarDocs("/docs")`: Modern, responsive Scalar UI.
- `adapters.WithSwaggerUIDocs("/docs")`: Classic Swagger UI.
- `adapters.WithEnableDocs(bool, path...)`: Dynamically toggle docs (e.g. enable in staging, disable in production).
- `adapters.WithoutDocs()`: Completely disables documentation endpoints.

---

## Implemented Features

### Core Authentication & Sessions
- **Email & Password Authentication**: Standard sign-up, sign-in, email verification, password reset, and password updates.
- **Session Management**: Multi-device sessions, session revocation (`/revoke-session`, `/revoke-sessions`, `/revoke-other-sessions`), session updates, and sliding-window expiration.
- **Cookie Cache Tier**: Sub-millisecond session validation using cryptographic HMAC-signed cookie cache, reducing database lookups on authenticated requests.
- **Account Management**: Multiple credential account linking, unlinking, and user deletion with dependency cleanup.

### Security & Hardening
- **Route Security Policies**:
  - `RequireFreshOps`: Re-authentication freshness enforcement on high-risk operations (e.g. email change, password update, account deletion, org deletion).
  - `RequireBearerTokenOps`: Restricts sensitive endpoints to genuine sessions/bearer tokens, rejecting short-lived Access JWTs with configurable pass-through or rejection.
  - `DisabledOps` & `DisabledPaths`: Mount-level or middleware-level operation/route disabling.
- **CSRF & Origin Protection**: Origin and Referer validation on mutating requests across core and plugin routes (`CheckOriginOnPluginMutations`).
- **Secondary Storage Blacklists**: Redis and in-memory cache abstractions for revoked sessions and rate limits.
- **Global Rate Limiter** (`AuthConfig.RateLimit`, better-auth's `rateLimit`): see below.

### Core Options (better-auth parity)

These `config.AuthConfig` fields port better-auth's options of the same name:

| Option | better-auth | Behaviour |
|---|---|---|
| `RateLimit` | `rateLimit` | One limiter in front of every core and plugin route, per client IP (`Advanced.IPAddress`) and path. `Enabled` (`*bool`) defaults to production only (`GOAUTH_ENV`/`GO_ENV`/`APP_ENV`/`NODE_ENV` = `production`). Default rule 100 requests / 10 s; special rules: `/sign-in*`, `/sign-up*`, `/change-password`, `/change-email` 3 / 10 s, password-reset and verification e-mails 3 / 60 s; plugin rules (`plugins.RateLimitProvider`); `CustomRules` (exact path or wildcard, `Disabled`, per-request `Resolve`). `Storage`: `memory`, `secondary-storage` (same keys and JSON as better-auth, so a TypeScript server can share Redis) or `CustomStorage`. A limited request gets `429` `{"message":"Too many requests. Please try again later."}` with `X-Retry-After`. |
| `Hooks.Before` / `Hooks.After` | `hooks.before` / `hooks.after` | Endpoint middleware (`src/common/endpointhooks`): before hooks can change the request body/headers/query, answer instead of the endpoint or fail it; after hooks see the response and the new session and can replace it. Plugins add hooks with `plugins.EndpointHooksProvider`. |
| `OnAPIError` | `onAPIError` | `ErrorURL` replaces the `<baseURL><basePath>/error` page (OAuth callbacks, `GET /error`); `OnError(err, r)` receives unexpected errors and errors raised before the endpoint (origin check, before hooks); `Throw` panics with them instead. |
| `Logger` | `logger` | `Level` (`debug` … `error`, default `warn`), `Disabled`, custom `Log` func; default output is `slog`. |
| `Advanced.BackgroundTasks.Handler` | `advanced.backgroundTasks.handler` | Runs senders (verification/reset e-mails, OTPs, magic links, invitations) without blocking the response, e.g. `func(task func()) { go task() }`; their errors are then logged. Default: synchronous. |
| `Secrets` (`[]config.SecretVersion{{Version, Value}}`, or `$BETTER_AUTH_SECRETS` = `"2:new,1:old"`) | `secrets` | Secret rotation. The first entry signs cookies / tokens and encrypts new data as `$ba$<version>$<hex>` envelopes (two-factor secrets and backup codes, OTPs, OAuth tokens, JWKS private keys, OAuth state, JWE cookie caches); older versions still decrypt, and the old `Secret` decrypts bare-hex data written before rotation. goauth also accepts cookie signatures made with older versions, so users stay signed in across a rotation (better-auth only checks the current secret). Data and cookies written by a TypeScript better-auth with the same secrets are read as is. |
| `SocialProviders` (`[]providers.Provider`) + `Account.*` | `socialProviders` + `account` | Installs the social plugin (`/sign-in/social`, `/callback/{id}`, `/link-social`, `/get-access-token`, `/refresh-token`, `/account-info`) configured from `Account` (`AccountLinking`, `EncryptOAuthTokens`, `UpdateAccountOnSignIn`, `StoreStateStrategy`, `SkipStateCookieCheck`). Passing `social.New(...)` as well merges the providers (the same id twice is an error). generic-oauth providers are social providers too (their callback is `/oauth2/callback/{id}`). |
| `Account.StoreAccountCookie` | `account.storeAccountCookie` | Keeps the signed-in provider account in the encrypted `account_data` cookie (JWE, chunked above 4 KB): `/account-info` works without `accountId`, `/get-access-token` and `/refresh-token` read and refresh it; sign-out deletes it. |
| `TrustedOriginsFunc func(*http.Request) []string` | `trustedOrigins: (request) => [...]` | Origins computed per request, used by the origin/CSRF check and redirect validation (`TrustedOrigins` stays the static list). |
| `DynamicBaseURL` (`AllowedHosts`, `Fallback`, `Protocol`) | `baseURL: { allowedHosts, fallback, protocol }` | The base URL is taken from the request host (`X-Forwarded-Host`/`-Proto` trusted unless `Advanced.TrustedProxyHeaders` is false) when it matches an allowed host pattern (`*.vercel.app`); otherwise the fallback, or `400 HOST_NOT_ALLOWED`. Links in e-mails, OAuth redirect URIs, error redirects and trusted origins follow the request host. |
| `Advanced.Cookies` / `Advanced.DefaultCookieAttributes` | `advanced.cookies` / `advanced.defaultCookieAttributes` | Per-cookie name and attributes (`Domain`, `Path`, `Secure`, `HTTPOnly`, `SameSite`, `Partitioned`), keyed by the cookie name without prefix (`session_token`, `session_data`, `dont_remember`, `account_data`, ...); renamed cookies keep the `__Secure-` prefix rule. |
| `Verification.StoreIdentifier` / `StoreIdentifierOverrides` | `verification.storeIdentifier` (`plain` / `hashed` / `{hash}`, `{default, overrides}`) | Verification identifiers (reset tokens, OTP keys, OAuth state, ...) are stored as SHA-256 base64url (or a custom hash); rows written before keep working through a plain fallback lookup. |

```go
cfg := config.AuthConfig{
	RateLimit: config.RateLimitOptions{
		Enabled: new(true),
		CustomRules: map[string]ratelimit.CustomRule{
			"/sign-in/email": {Window: time.Minute, Max: 5},
			"/get-session":   {Disabled: true},
		},
	},
	Hooks: config.HooksOptions{
		Before: func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			if c.Path == "/sign-up/email" && !strings.HasSuffix(fmt.Sprint(c.Body["email"]), "@example.com") {
				return nil, autherr.New("EMAIL_DOMAIN_NOT_ALLOWED", "Email domain not allowed", http.StatusBadRequest)
			}
			return nil, nil
		},
	},
	OnAPIError: config.OnAPIErrorOptions{ErrorURL: "https://app.example.com/auth-error"},
	Logger:     logger.Options{Level: logger.LevelInfo},
	Advanced:   config.Advanced{BackgroundTasks: config.BackgroundTasks{Handler: func(task func()) { go task() }}},
}
```

```go
// betterAuth({ secrets, socialProviders, account, baseURL: { allowedHosts }, trustedOrigins, advanced, verification })
cfg := config.AuthConfig{
	Secrets: []config.SecretVersion{
		{Version: 2, Value: os.Getenv("AUTH_SECRET_V2")}, // signs and encrypts
		{Version: 1, Value: os.Getenv("AUTH_SECRET_V1")}, // still decrypts / verifies
	},
	SocialProviders: []providers.Provider{
		providers.GitHub(providers.GitHubOptions{ProviderOptions: providers.ProviderOptions{ClientID: id, ClientSecret: secret}}),
	},
	Account: config.AccountOptions{StoreAccountCookie: true, EncryptOAuthTokens: true},
	DynamicBaseURL: &config.DynamicBaseURL{
		AllowedHosts: []string{"myapp.com", "*.vercel.app"},
		Fallback:     "https://myapp.com",
	},
	TrustedOriginsFunc: func(r *http.Request) []string { return tenantOrigins(r) },
	Advanced: config.Advanced{
		DefaultCookieAttributes: &config.CookieAttributes{SameSite: "none", Secure: new(true), Partitioned: new(true)},
		Cookies: map[string]config.CookieOverride{"session_token": {Name: "myapp.sid"}},
	},
	Verification: config.VerificationOptions{StoreIdentifier: config.StoreIdentifierOption{Mode: config.StoreIdentifierHashed}},
}
```

### Official Plugins

| Plugin | Package | Description |
|---|---|---|
| **Organization** | `src/plugins/org` | Multi-tenancy, org creation/approval, member invitations, team scoping, self-service leave, admin search, and two-tier dynamic RBAC with sub-microsecond L1 memory caching. |
| **Admin** | `src/plugins/admin` | User management, platform role assignment (`admin`/`user`), user ban/unban, user impersonation, and admin user removal. |
| **Bearer** | `src/plugins/bearer` | HMAC-signed opaque bearer tokens (`<token>.<sig>`) for mobile, CLI, and non-cookie clients with strict signature validation (`RequireSignature`). |
| **Access-Token** | `src/plugins/access-token` | Short-lived Access JWT + refresh token flow with live claim synchronization (Layer 1) and automatic `set-auth-token` header emission on active org/team changes (Layer 2). |
| **Email OTP** | `src/plugins/email-otp` | Time-sensitive one-time passcodes for sign-in and verification with enumeration defense, rate limiting, and global email verification override. |
| **JWT / JWKS** | `src/plugins/jwt` | OpenID/OAuth-compatible JWT issuance and public JWKS endpoint (`/.well-known/jwks.json`). |

---

## Better Auth Compatibility Status

| Feature / Domain | Better Auth (TS) | Better Go Auth | Status |
|---|:---:|:---:|:---:|
| **Core Endpoints (`/sign-up`, `/sign-in`, `/get-session`, etc.)** | Supported | Supported | Verified with `better-auth/client` |
| **Session Cookies (`better-auth.session_token`)** | Supported | Supported | Full Interoperability |
| **Password Hashes (Argon2id)** | Supported | Supported | Full Interoperability |
| **Organization & Teams Plugin** | Supported | Supported | Verified Parity |
| **Admin Plugin** | Supported | Supported | Verified Parity |
| **Bearer Token Plugin** | Supported | Supported | Verified Parity |
| **Email OTP Plugin** | Supported | Supported | Verified Parity |
| **JWT & JWKS Plugin** | Supported | Supported | Verified Parity |
| **Multi-Database Support (SQLite, Postgres, MySQL)** | Supported | Supported | Verified with Testcontainers |
| **OAuth 2.0 / Social Sign-In** | Supported | *Planned* | In Roadmap |
| **Passkeys / WebAuthn** | Supported | *Planned* | In Roadmap |
| **Two-Factor Authentication (2FA / TOTP)** | Supported | *Planned* | In Roadmap |
| **Magic Link Authentication** | Supported | *Planned* | In Roadmap |
| **Phone Number (SMS) Authentication** | Supported | *Planned* | In Roadmap |
| **Custom Database Fields** | Supported | *Planned* | Phase 8 Specification |

---

## Planned Features & Roadmap

1. **OAuth 2.0 & Social Providers**:
   - Out-of-the-box provider integrations (Google, GitHub, Discord, Apple, Microsoft, etc.) matching Better Auth's social flow and account linking.
2. **Two-Factor Authentication (2FA / MFA)**:
   - Time-based One-Time Passwords (TOTP via Google Authenticator, Authy), backup recovery codes, and SMS 2FA.
3. **Passkeys & WebAuthn**:
   - Passwordless registration and login via FIDO2/WebAuthn credentials.
4. **Magic Link**:
   - Passwordless email sign-in using secure, signed single-use verification links.
5. **Phone Number Authentication**:
   - SMS OTP sign-in, phone number verification, and profile management.
6. **Physical Custom Fields (Phase 8)**:
   - Dynamic schema migrations and repository serialization for custom fields added to `user`, `session`, and `organization` tables.
7. **Native Multi-ORM Expansion (Phase 7)**:
   - Native [Bun](https://bun.uptrace.dev/), [sqlc](https://sqlc.dev/), and standard `database/sql` repository implementations.

---

## Testing

The project maintains comprehensive test coverage across unit, integration, and compatibility suites:

```bash
# Run all unit tests
go test ./...

# Run compatibility test suite
go test -v ./src/tests/compat/...

# Run router adapter tests
go test -v ./adapters/...
```

Multi-database integration tests use [testcontainers-go](https://github.com/testcontainers/testcontainers-go) to test against live PostgreSQL and MySQL instances in Docker.

---

## License

This project is licensed under the [MIT License](LICENSE).

