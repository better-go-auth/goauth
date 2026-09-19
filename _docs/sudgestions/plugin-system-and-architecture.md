# Better-Go-Auth: Architectural Improvements & Plugin System Design

This document details recommendations to enhance the robustness, extensibility, and ergonomics of **Better-Go-Auth**, with special focus on the **plugin system**, **dependency management**, and **authentication flow**.

---

## Table of Contents
1. [Plugin Lifecycle & Initialization](#1-plugin-lifecycle--initialization)
2. [Plugin Registry & Retrieval (`GoAuth`)](#2-plugin-registry--retrieval-goauth)
3. [Lifecycle Hooks (Cross-Plugin Communication)](#3-lifecycle-hooks-cross-plugin-communication)
4. [Dependency Injection & DB Decoupling](#4-dependency-injection--db-decoupling)
5. [Routing Architecture: Huma vs Framework Agnostic](#5-routing-architecture-huma-vs-framework-agnostic)
6. [Authentication Ergonomics: Eliminating Double-Auth](#6-authentication-ergonomics-eliminating-double-auth)
7. [Transaction Propagation (`TxManager`)](#7-transaction-propagation-txmanager)
8. [Codebase Hygiene & Consistency](#8-codebase-hygiene--consistency)
9. [Prioritized Implementation Matrix](#9-prioritized-implementation-matrix)

---

## 1. Plugin Lifecycle & Initialization

### The Issue
In `goauth.go: SetupGoAuth`, plugins are currently processed in a single loop:
```go
for _, p := range opts.Plugins {
    if err := p.Init(initCtx); err != nil { ... } // Mounts HTTP routes inside Init()
    if mig := p.Migrator(); mig != nil {
        mig.Migrate(context.Background())         // Runs migrations AFTER routes are mounted
    }
}
```
1. **Race Condition**: Routes are live before database tables/columns are migrated.
2. **Inter-Plugin Dependencies**: If Plugin B references a table created by Plugin A, sequential execution without separation of migration and route-mounting can fail.

### Proposed Multi-Phase Lifecycle
Separate startup into distinct, deterministic phases:

```
┌────────────────────────────────────────────────────────┐
│ 1. Core Schema Migration (Users, Accounts, Sessions)   │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ 2. Plugin Migrations (All plugins run Migrator)        │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ 3. Plugin Initialization (Services, Repositories,      │
│    Event Hook Subscriptions)                           │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ 4. Route Mounting (Core routes + Plugin routes mounted │
│    with full confidence that all DB tables exist)      │
└────────────────────────────────────────────────────────┘
```

#### Code Pattern:
```go
// Phase 1: Core Migrations
if err := core_migration.Migrate(opts.Conn); err != nil {
    return nil, fmt.Errorf("core migration failed: %w", err)
}

// Phase 2: Plugin Migrations
for _, p := range opts.Plugins {
    if mig := p.Migrator(); mig != nil {
        if err := mig.Migrate(context.Background()); err != nil {
            return nil, fmt.Errorf("plugin %s migration failed: %w", p.ID(), err)
        }
    }
}

// Phase 3: Plugin Init
for _, p := range opts.Plugins {
    if err := p.Init(initCtx); err != nil {
        return nil, fmt.Errorf("plugin %s init failed: %w", p.ID(), err)
    }
}

// Phase 4: Mount Routes
for _, p := range opts.Plugins {
    if r, ok := p.(RoutablePlugin); ok {
        r.RegisterRoutes(api, mdlWare)
    }
}
```

---

## 2. Plugin Registry & Retrieval (`GoAuth`)

### The Issue
In `SetupGoAuth`, `pluginMap := make(map[string]plugin.Plugin)` is populated during startup but is **never attached to the `GoAuth` struct**. 

Callers configuring auth have no way to access initialized plugin services from the returned `*GoAuth` instance:
```go
auth, err := bettergoauth.SetupGoAuth(api, opts)
// How does an application controller get orgService or adminService from `auth`?
// Currently: impossible without passing external pointers.
```

### Proposed Solution
1. Add `Plugins map[string]plugin.Plugin` to `GoAuth`.
2. Provide a generic, type-safe helper function:

```go
// In goauth.go:
type GoAuth struct {
    Options           GoAuthOptions
    Plugins           map[string]plugin.Plugin
    IAuthServices     serv_interfaces.IAuthServices
    MiddleWare        middleware.AuthMiddleware
    RevocationStore   middleware.RevocationStore
    TransactionManager interfaces.ITransactionManager
    Provider          *providers.IProviderS
}

// GetPlugin retrieves a plugin by ID with compile-time type casting:
func GetPlugin[T any](g *GoAuth, id string) (T, bool) {
    p, ok := g.Plugins[id]
    if !ok {
        var zero T
        return zero, false
    }
    typed, ok := p.(T)
    return typed, ok
}
```

#### Usage in Application Code:
```go
orgPlugin, ok := bettergoauth.GetPlugin[*org.Plugin](auth, "org")
if ok {
    orgService := orgPlugin.Service()
    orgService.GetOrganization(ctx, "org_123")
}
```

---

## 3. Lifecycle Hooks (Cross-Plugin Communication)

### The Issue
Plugins currently cannot communicate or react to auth lifecycle events without introducing direct code dependencies on each other.

Common auth requirements:
- When a user is deleted or banned in `admin` $\rightarrow$ clean up their organization memberships, revoke their API keys, and invalidate their active sessions.
- When an organization is deleted $\rightarrow$ clear `active_organization_id` from user sessions.
- When a new session is created $\rightarrow$ allow plugins to inject custom claims into the JWT or session metadata.

### Proposed Solution
Provide an event-driven `HookRegistry` inside `InitContext`:

```go
type HookRegistry interface {
    // User Lifecycle
    OnBeforeUserCreate(fn func(ctx context.Context, user *models.User) error)
    OnAfterUserCreate(fn func(ctx context.Context, user *models.User) error)
    OnUserDeleted(fn func(ctx context.Context, userID string) error)
    OnUserBanned(fn func(ctx context.Context, userID string, reason *string) error)

    // Session Lifecycle
    OnBeforeSessionCreate(fn func(ctx context.Context, session *models.Session, claims *crypto.CustomClaims) error)
    OnSessionRevoked(fn func(ctx context.Context, sessionID string) error)

    // Organization Lifecycle
    OnActiveOrgChanged(fn func(ctx context.Context, userID, newOrgID string) error)
}
```

#### Plugin Registration Example:
```go
// Inside org/plugin.go:
func (p *Plugin) Init(ictx *plugins.InitContext) error {
    ...
    if ictx.Hooks != nil {
        ictx.Hooks.OnUserDeleted(func(ctx context.Context, userID string) error {
            return p.service.RemoveUserFromAllOrganizations(ctx, userID)
        })
    }
    return nil
}
```

---

## 4. Dependency Injection & DB Decoupling

### The Issue
Currently, plugins must be instantiated with a `*gorm.DB` instance before `SetupGoAuth` is even called:
```go
adminPlugin := admin.NewWithGorm(gormDB, ...)
orgPlugin := org.NewWithGorm(gormDB, ...)

auth, err := bettergoauth.SetupGoAuth(api, GoAuthOptions{
    Conn: gormDB, // Passed 3 times!
    Plugins: []plugin.Plugin{adminPlugin, orgPlugin},
})
```
`InitContext.Extras` was envisioned for this, but is initialized to an empty map `map[string]any{}`.

### Proposed Solution
Let `InitContext` supply the database connection or repository factory directly to the plugin during `Init()`:

```go
type InitContext struct {
    Ctx           context.Context
    Api           huma.API
    Config        config.AuthConfig
    DB            *gorm.DB                  // First-class connection
    TxManager     interfaces.ITransactionManager
    IAuthServices serv_interfaces.IAuthServices
    IAuthRepos    repo_interfaces.IAuthRepos
    MiddleWare    *middleware.AuthMiddleware
    Authenticate  authenticator.AuthenticateFunc
    Hooks         HookRegistry
    Extras        map[string]any
}
```

This simplifies plugin configuration to options and business rules:
```go
// Clean, declarative plugin instantiation:
auth, err := bettergoauth.SetupGoAuth(api, GoAuthOptions{
    Conn: gormDB,
    Plugins: []plugin.Plugin{
        admin.New(admin.WithAdminRoles(enums.Admin)),
        org.New(orgconfig.OrgConfig{AllowUserCreateOrg: true}),
    },
})
```
Inside `Init(ictx)`, the plugin initializes its own GORM repositories from `ictx.DB` if repositories were not manually overridden.

---

## 5. Routing Architecture: Huma vs Framework Agnostic

### The Issue
In `src/plugins/plugins-interface.go`:
```go
type Plugin interface {
    Routes() []RouteDescriptor // returns net/http handlers
}
```
1. In reality, both `admin` and `org` return `nil` for `Routes()` and expose `SetupHumaRoutes(api huma.API, mdlware *middleware.AuthMiddleware)`.
2. `InitContext` already contains `Api huma.API`.
3. Better-Go-Auth heavily relies on Huma for OpenAPI 3.1 documentation, operation IDs, auto-generated JSON validation, and typed inputs/outputs.

### Proposed Solution
Acknowledge Huma as the first-class API engine for Better-Go-Auth, while retaining an adapter interface for optional framework flexibility:

```go
// RoutablePlugin is implemented by plugins that expose API endpoints via Huma.
type RoutablePlugin interface {
    RegisterHumaRoutes(api huma.API, mdlware *middleware.AuthMiddleware)
}
```
This eliminates the unused `Routes() []RouteDescriptor` boilerplate and unifies route registration cleanly.

---

## 6. Authentication Ergonomics: Eliminating Double-Auth

### The Issue
On protected routes:
```go
// 1. Middleware validates JWT and injects claims into ctx:
huma.Register(api, huma.Operation{
    Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(...)},
}, h.CreateOrg)
```
Yet inside the handler:
```go
// 2. Input DTO embeds AuthHeaders (polluting OpenAPI parameters with header/cookie docs):
type CreateOrgInput struct {
    humatypes.AuthHeaders
    Body orgdtos.CreateOrgInput
}

// 3. Handler calls Authenticate AGAIN:
func (h *OrgHandler) CreateOrg(ctx context.Context, input *CreateOrgInput) (...) {
    session, err := h.Authenticate(ctx, input.AuthHeaders)
    ...
}
```

### Proposed Solution
Introduce a fast, zero-overhead Context Session extractor:

```go
// In src/providers/authenticator or src/app/core/session:
func SessionFromContext(ctx context.Context) (*dtos.SessionResponse, bool) {
    // 1. Direct session object in context (if set by middleware)
    if sess, ok := ctx.Value(consts.CtxSession).(*dtos.SessionResponse); ok && sess != nil {
        return sess, true
    }
    // 2. Fallback to claims in context
    if claims, ok := ctx.Value(consts.CtxClaims.Str()).(*crypto.CustomClaims); ok && claims != nil {
        return sessionResponseFromClaims(claims, ""), true
    }
    return nil, false
}
```

#### Updated Handler:
```go
func (h *OrgHandler) CreateOrg(ctx context.Context, input *CreateOrgInput) (*humatypes.HumaRes[orgdtos.OrgResponse], error) {
    session, ok := authenticator.SessionFromContext(ctx)
    if !ok {
        return nil, huma.Error401Unauthorized("unauthorized")
    }

    org, err := h.Org.CreateOrganization(ctx, session.User.ID, input.Body)
    if err != nil {
        return nil, humatypes.RespondErr(err)
    }
    return new(humatypes.MakeRes(*orgdtos.OrgToResponse(org), http.StatusCreated)), nil
}
```
*Benefits:*
- **Cleaner DTOs**: No need to embed `humatypes.AuthHeaders` in every endpoint.
- **Accurate OpenAPI documentation**: Authentication is documented via OpenAPI Security Schemes (`bearerAuth`, `cookieAuth`) rather than duplicate parameters on every route.
- **Performance**: Skips redundant string parsing and map lookups on every request.

---

## 7. Transaction Propagation (`TxManager`)

### The Issue
`InitContext` provides `TxManager interfaces.ITransactionManager`, but plugins execute database operations on `r.db.WithContext(ctx)` directly.
If an operation requires creating an organization and updating the user's active session within a single atomic database transaction, the transaction boundary cannot be shared.

### Proposed Solution
Standardize on context-bound GORM transactions using `gormutil.GetDB(ctx, r.db)`:

```go
// Transaction manager binds the *gorm.DB transaction to context:
func (m *GormTxManager) RunInTx(ctx context.Context, fn func(txCtx context.Context) error) error {
    return m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
        txCtx := context.WithValue(ctx, consts.TxKey, tx)
        return fn(txCtx)
    })
}

// In repository methods across all plugins:
func (r *OrgRepo) CreateOrg(ctx context.Context, org *models.Organization) error {
    db := gormutil.GetDB(ctx, r.db) // If a transaction is active in ctx, uses `tx`; otherwise uses `r.db`
    return db.Create(org).Error
}
```

---

## 8. Codebase Hygiene & Consistency

| Category | Finding | Recommendation |
|---|---|---|
| **Typo** | `TransctionManager` in `goauth.go: GoAuth` | Rename to `TransactionManager` |
| **Typo** | `orgReops` in `src/plugins/org/plugin.go` | Rename to `orgRepos` |
| **Naming** | `CompanyId` in `crypto.CustomClaims` vs `OrganizationID` in org models | Standardize on `OrganizationID` / `OrgID` across all claims and models |
| **Imports** | `loc_conf` and `config1` aliases in test & handler files | Rename local config packages to `adminconfig` and `orgconfig` to eliminate shadowing |
| **Error Handling** | Inconsistent error envelopes (`huma.NewError`, `autherr.ErrUnauthorized`, `humatypes.RespondErr`) | Standardize on a single `humatypes.ToStatusError(err)` helper that guarantees Better Auth's `{"code": "...", "message": "..."}` JSON format |

---

## 9. Implementation Matrix & Status

| Task | Section | Status | Notes |
|---|---|---|---|
| Re-order startup lifecycle (Migrations $\rightarrow$ Init $\rightarrow$ Routes) | [Section 1](#1-plugin-lifecycle--initialization) | **Implemented** | Migrations for all plugins run before plugin initialization in `SetupGoAuth` |
| Add `Plugins` map, `Plugin(id)` & `GetPlugin[T]` to `GoAuth` | [Section 2](#2-plugin-registry--retrieval-goauth) | **Implemented** | Available on `GoAuth` with generic type-safe access |
| Lifecycle Hook Registry (`HookRegistry`, `NewHookRegistry`) | [Section 3](#3-lifecycle-hooks-cross-plugin-communication) | **Implemented** | Implemented in `src/plugins/hooks.go` and exposed via `InitContext.Hooks` |
| Inject DB via `InitContext` | [Section 4](#4-dependency-injection--db-decoupling) | *Skipped* | Explicitly excluded per user instruction |
| Route interface refactoring | [Section 5](#5-routing-architecture-huma-vs-framework-agnostic) | *Skipped* | Explicitly excluded per user instruction |
| Context-based session extraction (`SessionFromContext`) | [Section 6](#6-authentication-ergonomics-eliminating-double-auth) | **Implemented** | Added `SessionFromContext` and fast-path in `OrgHandler` & `AdminHandler` |
| Standardize transaction propagation (`gormutil.GetDB`) | [Section 7](#7-transaction-propagation-txmanager) | **Implemented** | Org and Admin GORM repos now use common `gormutil.GetDB` for shared transactions |
| Typos, `TransactionManager`, and `OrgId` migration | [Section 8](#8-codebase-hygiene--consistency) | **Implemented** | `TransactionManager` added, `orgRepos` typo fixed, `OrgId` used throughout |

