# 02: Architecture Decoupling Strategy

## 1. Current Coupling Analysis

To make `better-go-auth` (`goauth`) truly database-agnostic, we must first examine where GORM is currently coupled into the core domain and plugin layers.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CURRENT GORM COUPLING                           │
├───────────────────────┬────────────────────────────────────────────────┤
│ Domain Models         │ Leaks `gorm.DeletedAt` into `User`, `Org`,     │
│ (`src/models/`)       │ `Team`. Hooks import `*gorm.DB` & schema.Namer │
├───────────────────────┼────────────────────────────────────────────────┤
│ Transaction Manager   │ `gormutil.GormTxManager` stores `*gorm.DB` in  │
│ (`src/common/`)       │ context under `gormutil.TxKey`                 │
├───────────────────────┼────────────────────────────────────────────────┤
│ Migration Engine      │ `core_migration.GORMMigrator` directly runs    │
│ (`src/models/migr/`)  │ `db.AutoMigrate(...)` and GORM-specific DDL    │
├───────────────────────┼────────────────────────────────────────────────┤
│ Dynamic Queries       │ Some repo methods rely on GORM Clauses / Maps  │
└───────────────────────┴────────────────────────────────────────────────┘
```

### 1.1. Specific Leakage Points
1. **`models.User.DeletedAt`**:
   - Currently declared as `gorm.DeletedAt gorm.DeletedAt`.
   - **Problem**: Any service or adapter importing `models.User` is forced to depend on `gorm.io/gorm`. A project using `sqlc` or `bun` should not import GORM.
2. **Lifecycle Hooks**:
   - `BeforeSave(*gorm.DB) error` on `Session` (used to convert `ExpiresAt` to UTC).
   - `TableName(namer schema.Namer)` on `Session` and `User`.
3. **Context Transaction Extraction**:
   - Repositories call `gormutil.GetDB(ctx, r.db)` which casts `ctx.Value(TxKey)` specifically to `*gorm.DB`.
4. **Auto-Migration Dependence**:
   - Plugins (`org`, `admin`, `jwt`) assume an ORM with automatic schema reflection (`db.AutoMigrate`) exists.

---

## 2. Decoupling Roadmap: The 4 Pillars

```
┌────────────────────────────────────────────────────────────────────────┐
│                 THE 4 PILLARS OF ORM AGNOSTICISM                       │
├──────────────────┬─────────────────────────────────────────────────────┤
│ 1. Domain Models │ Pure Go primitives (`*time.Time`), zero ORM types   │
│ 2. Transactions  │ Generic, context-propagated ITransactionManager     │
│ 3. Error Mapping │ Unified autherr mappings across drivers and engines │
│ 4. Migrations    │ Dual-mode migrations: Code-First & Embedded SQL DDL │
└──────────────────┴─────────────────────────────────────────────────────┘
```

---

## 3. Pillar 1: Pure Go Domain Models

### 3.1. Removing `gorm.DeletedAt`
Replace `gorm.DeletedAt` in all domain models with a standard Go pointer:
```go
// BEFORE (coupled to GORM):
type User struct {
    Base      `mapstructure:",squash"`
    UserDto   `mapstructure:",squash"`
    DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// AFTER (ORM-neutral):
type User struct {
    Base      `mapstructure:",squash"`
    UserDto   `mapstructure:",squash"`
    DeletedAt *time.Time `json:"deletedAt,omitempty" gorm:"index" bun:"deleted_at,soft_delete"`
}
```

#### Why this works across all ORMs:
- **GORM**: Handles `*time.Time` natively as a soft-delete column when tagged with `gorm:"index"`.
- **Bun**: Natively supports `*time.Time` as soft-delete when tagged with `bun:",soft_delete"`.
- **sqlc / sqlx / database/sql**: Maps directly to nullable `TIMESTAMPTZ` / `DATETIME` (`sql.NullTime` or `*time.Time`).
- **Ent**: Ent uses its own code-generated fields; mapping to `*time.Time` is effortless.

### 3.2. Struct Tag Strategy: Multi-Tag vs Separate DTOs
We have two architectural options for struct tags:

| Option | Approach | Pros | Cons |
| :--- | :--- | :--- | :--- |
| **A: Unified Multi-Tagged Models** *(Recommended)* | Shared models have tags: `json:"..."`, `gorm:"..."`, `bun:"..."`, `db:"..."` | Single source of truth; zero copying between domain and DB structs | Struct definitions have multiple tag attributes |
| **B: Strict Hexagonal DTO Isolation** | Pure domain structs (JSON only) + separate DB structs for each ORM | 100% clean domain layer | Requires 2x maintenance and mapping functions for every entity |

**Decision**: **Option A** for core entities (`User`, `Session`, `Account`, `Verification`, `OrgRole`), because:
1. `goauth` already tags fields with both `gorm:` and `bun:`.
2. Go struct tags are inert metadata; non-GORM adapters simply ignore `gorm:` tags, and non-Bun adapters ignore `bun:` tags.
3. For `sqlc` and `ent`, they generate their own database structs anyway, so their adapters will perform direct mapping regardless.

### 3.3. Neutralizing Lifecycle Hooks
Instead of ORM-specific hooks like `BeforeSave(*gorm.DB)`, define a standard hook interface:
```go
type BeforeSaver interface {
    BeforeSave() error
}
```
For `Session.ExpiresAt` UTC conversion:
```go
func (s *Session) EnsureUTC() {
    if !s.ExpiresAt.IsZero() {
        s.ExpiresAt = s.ExpiresAt.UTC()
    }
}
```
Each repository adapter calls `session.EnsureUTC()` prior to executing `INSERT` or `UPDATE`.

---

## 4. Pillar 2: Generic Transaction Management

### 4.1. The Universal Transaction Interface
The project already defines `interfaces.ITransactionManager`:
```go
package interfaces

import "context"

type ITransactionManager interface {
    Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}
```

### 4.2. Context Key Isolation by Adapter
Instead of a single global key, each adapter manages its own transaction context key:

```go
// For GORM:
package gormauth
type ctxKey struct{}
var txKey = ctxKey{}

func WithTx(ctx context.Context, tx *gorm.DB) context.Context {
    return context.WithValue(ctx, txKey, tx)
}
func GetDB(ctx context.Context, fallback *gorm.DB) *gorm.DB {
    if tx, ok := ctx.Value(txKey).(*gorm.DB); ok {
        return tx.WithContext(ctx)
    }
    return fallback.WithContext(ctx)
}

// For Bun:
package bunauth
type ctxKey struct{}
var txKey = ctxKey{}

func WithTx(ctx context.Context, tx bun.Tx) context.Context {
    return context.WithValue(ctx, txKey, tx)
}
func GetDB(ctx context.Context, fallback *bun.DB) bun.IDB {
    if tx, ok := ctx.Value(txKey).(bun.Tx); ok {
        return tx
    }
    return fallback
}

// For database/sql & sqlx:
package stdsql
type ctxKey struct{}
var txKey = ctxKey{}

func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
    return context.WithValue(ctx, txKey, tx)
}
func GetExecutor(ctx context.Context, fallback DBExecutor) DBExecutor {
    if tx, ok := ctx.Value(txKey).(*sql.Tx); ok {
        return tx
    }
    return fallback
}
```

### 4.3. Business Services Remain 100% Unaware
The business services (`AuthService`, `SessionService`, `OrgService`) invoke `s.tx.Transaction(ctx, func(txCtx context.Context) error { ... })`. They never know whether the transaction is powered by GORM, Bun, or `database/sql`.

---

## 5. Pillar 3: Database Error Normalization

Different database drivers and ORMs return completely different error types for identical failures (e.g., unique email violation or row not found).

### 5.1. Target Domain Errors (`src/common/autherr`)
`goauth` defines canonical domain errors:
- `autherr.ErrNotFound`: Record does not exist.
- `autherr.ErrDuplicateEmail`: User email already exists.
- `autherr.ErrConflict`: Unique constraint violation (e.g. account provider ID or token conflict).
- `autherr.ErrForeignKey`: Referenced foreign entity does not exist.

### 5.2. Error Classifier Utility
Each adapter passes driver errors through a dialect-aware normalizer:

```go
package dbutil

import (
    "database/sql"
    "errors"
    "strings"

    "github.com/better-go-auth/goauth/src/common/autherr"
    "github.com/jackc/pgx/v5/pgconn"
    "github.com/go-sql-driver/mysql"
    "modernc.org/sqlite" // or mattn/go-sqlite3
)

func NormalizeError(err error) error {
    if err == nil {
        return nil
    }
    if errors.Is(err, sql.ErrNoRows) {
        return autherr.ErrNotFound
    }

    // PostgreSQL Error Handling
    var pgErr *pgconn.PgError
    if errors.As(err, &pgErr) {
        switch pgErr.Code {
        case "23505": // unique_violation
            if strings.Contains(pgErr.ConstraintName, "email") {
                return autherr.ErrDuplicateEmail
            }
            return autherr.ErrConflict
        case "23503": // foreign_key_violation
            return autherr.ErrForeignKey
        }
    }

    // MySQL Error Handling
    var mysqlErr *mysql.MySQLError
    if errors.As(err, &mysqlErr) {
        switch mysqlErr.Number {
        case 1062: // ER_DUP_ENTRY
            if strings.Contains(mysqlErr.Message, "email") {
                return autherr.ErrDuplicateEmail
            }
            return autherr.ErrConflict
        case 1452: // ER_NO_REFERENCED_ROW_2
            return autherr.ErrForeignKey
        }
    }

    // SQLite Error Handling
    msg := strings.ToLower(err.Error())
    if strings.Contains(msg, "unique constraint failed") {
        if strings.Contains(msg, "email") {
            return autherr.ErrDuplicateEmail
        }
        return autherr.ErrConflict
    }

    return err
}
```

---

## 6. Pillar 4: Dual-Track Migration Architecture

Because ORMs like `GORM` and `Bun` have automatic migration tools, whereas `database/sql`, `sqlx`, and `sqlc` require raw SQL DDL, `goauth` will provide:

1. **Embedded SQL DDL Scripts (`embed.FS`)**:
   - `migrations/sqlite/*.sql`
   - `migrations/postgres/*.sql`
   - `migrations/mysql/*.sql`
   - Ready to run directly with `database/sql`, `golang-migrate`, `goose`, or `sqlc`.
2. **`migration.IMigrator` Implementations**:
   - `gormauth.NewMigrator(db)`: Uses GORM `AutoMigrate`.
   - `bunauth.NewMigrator(db)`: Uses Bun schema creation or `bun/migrate`.
   - `stdsql.NewMigrator(db, dialect)`: Reads embedded SQL scripts and executes pending migrations sequentially.
