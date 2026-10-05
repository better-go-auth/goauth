# goauth → better-auth: migration plan v2 ("new")

This plan replaces the "compat layer" approach in `../03-roadmap.md` with a **native** approach:
goauth's own models, repositories, services and adapters become better-auth compatible, and the
temporary `compat/` package and `src/app/core/ba` endpoints disappear.

## Goals

1. **Database compatible with better-auth first.** Same tables, same columns, same meaning.
   Column names use snake_case for now (GORM default); camelCase is a later, optional step.
2. **More features on top**, never instead of:
   - goauth's access/refresh JWT flow keeps working, built on the same session table and services.
   - Extra goauth columns live at the **bottom** of each model, after a
     `// ===== goauth fields (not in better-auth) =====` comment.
   - Extra goauth options live in a dedicated `GoAuth` sub-struct of each config section;
     everything else mirrors better-auth's options exactly.
3. **Plugins in scope now:** admin and organization only. The JWT/JWKS plugin comes later.
4. **Structure like better-go-auth:** swappable repositories, framework adapters, framework-agnostic
   services, pluggable providers.
5. **Legacy core untouched:** `src/app/core/*` (the current `/login`, `/refresh`, `/profile`, … routes) stays
   as it is until its services are rewired onto the new ones; it never blocks the better-auth endpoints.

## Documents

| File | Content |
|---|---|
| [01-structure.md](01-structure.md) | Target folder layout, what moves where |
| [02-schema.md](02-schema.md) | Table/column mapping for core, admin and organization |
| [03-config.md](03-config.md) | better-auth options ↔ Go config, and the `GoAuth` extension structs |
| [04-steps.md](04-steps.md) | Ordered steps with done-criteria, risks and tests |

## Status

| Step | State |
|---|---|
| 0. Providers extracted (`authcrypto`, `cookies`, `idgen` under `src/providers`) | ✅ done |
| 1–11 | see [04-steps.md](04-steps.md) |
