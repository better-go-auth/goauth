# 03: Detailed Implementation Plans by ORM

## 1. Overview & Directory Structure

To support all major Go ORMs and SQL access libraries, the repository structure will be organized with modular adapters under `src/app/repository/`:

```
src/app/repository/
├── repo_interfaces/         # Domain interfaces (IUserRepo, ISessionRepo, etc.)
├── repotest/                # Universal contract test suite (repotest.Run)
│
├── gormauth/                # GORM Adapter (existing, refactored)
├── bunauth/                 # Bun Adapter (uptrace/bun)
├── stdsql/                  # Raw database/sql & sqlx shared adapter
├── sqlcauth/                # sqlc Generated Code & Adapter
└── entauth/                 # Ent Generated Client & Adapter
```

---

## 2. Implementation Plan: `Bun` (`github.com/uptrace/bun`)

Bun is the fastest and most natural adapter to add because `goauth` models already feature `bun:"..."` struct tags.

### 2.1. What Needs to Be Added
1. **New Package**: `src/app/repository/bunauth/`
   - `user_repo.go`: Implements `repo_interfaces.IUserRepo`.
   - `session_repo.go`: Implements `repo_interfaces.ISessionRepo`.
   - `account_repo.go`: Implements `repo_interfaces.IOAuthAccountRepo`.
   - `verification_repo.go`: Implements `repo_interfaces.IVerificationRepo`.
   - `tx_manager.go`: Implements `interfaces.ITransactionManager`.
   - `migrator.go`: Implements `migration.IMigrator`.
   - `auth_repos.go`: Helper returning `repo_interfaces.IAuthRepos`.
2. **Plugin Adapter**: `src/plugins/org/repository/bun/` for organization, member, invitation, team, and dynamic role permissions.

### 2.2. Changes to Make in Existing Files
- **Models**:
  - Replace `gorm.DeletedAt` with `DeletedAt *time.Time` and tag `bun:"deleted_at,soft_delete"`.
  - Ensure all foreign keys have `bun:"rel:belongs-to,join:user_id=id"` tags.
- **Organization Role**:
  - `models.Permission` already implements `driver.Valuer` and `sql.Scanner`, which Bun consumes natively.

### 2.3. Concrete Code Blueprint (Bun)

#### Transaction Manager (`src/app/repository/bunauth/tx_manager.go`)
```go
package bunauth

import (
    "context"
    "github.com/better-go-auth/goauth/src/common/interfaces"
    "github.com/uptrace/bun"
)

type BunTxManager struct {
    db *bun.DB
}

func NewBunTxManager(db *bun.DB) interfaces.ITransactionManager {
    return &BunTxManager{db: db}
}

func (m *BunTxManager) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
    if _, ok := ctx.Value(txKey).(bun.Tx); ok {
        return fn(ctx) // Already inside transaction
    }
    return m.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
        txCtx := context.WithValue(ctx, txKey, tx)
        return fn(txCtx)
    })
}
```

#### User Repository (`src/app/repository/bunauth/user_repo.go`)
```go
package bunauth

import (
    "context"
    "database/sql"
    "errors"
    "fmt"
    "strings"

    "github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
    "github.com/better-go-auth/goauth/src/common/autherr"
    "github.com/better-go-auth/goauth/src/common/dtos"
    "github.com/better-go-auth/goauth/src/models"
    "github.com/uptrace/bun"
)

type UserRepo struct {
    db *bun.DB
}

func NewUserRepo(db *bun.DB) repo_interfaces.IUserRepo {
    return &UserRepo{db: db}
}

func (r *UserRepo) getDB(ctx context.Context) bun.IDB {
    if tx, ok := ctx.Value(txKey).(bun.Tx); ok {
        return tx
    }
    return r.db
}

func (r *UserRepo) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
    if user.ID == "" {
        user.ID = models.NewID()
    }
    user.Email = strings.ToLower(strings.TrimSpace(user.Email))

    _, err := r.getDB(ctx).NewInsert().Model(user).Exec(ctx)
    if err != nil {
        return nil, normalizeBunError(err)
    }
    return user, nil
}

func (r *UserRepo) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
    user := new(models.User)
    err := r.getDB(ctx).NewSelect().Model(user).
        Where("LOWER(email) = LOWER(?)", strings.TrimSpace(email)).
        Where("deleted_at IS NULL").
        Scan(ctx)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, autherr.ErrNotFound
        }
        return nil, err
    }
    return user, nil
}

func (r *UserRepo) UpdateUser(ctx context.Context, id string, data map[string]interface{}) (*models.User, error) {
    q := r.getDB(ctx).NewUpdate().Table(models.ResolveTableName(nil, models.ModelUser)).Where("id = ?", id)
    for col, val := range data {
        q = q.Set("? = ?", bun.Ident(col), val)
    }
    if _, err := q.Exec(ctx); err != nil {
        return nil, normalizeBunError(err)
    }
    return r.FindUserByID(ctx, id)
}
```

---

## 3. Implementation Plan: `sqlc` (`github.com/sqlc-dev/sqlc`)

`sqlc` compiles raw SQL files into type-safe Go code. It delivers maximum runtime performance with zero reflection.

### 3.1. What Needs to Be Added
1. **Directory**: `src/app/repository/sqlcauth/`
   - `sqlc.yaml`: Configuration specifying schema path, query paths, and generator settings.
   - `schema/`:
     - `schema_sqlite.sql`
     - `schema_postgres.sql`
     - `schema_mysql.sql`
   - `queries/`:
     - `users.sql`
     - `sessions.sql`
     - `accounts.sql`
     - `verifications.sql`
   - `generated/`: Output package generated by `sqlc generate`.
   - `user_repo.go`, `session_repo.go`, etc.: Wrapper structs implementing `repo_interfaces` by calling `generated.Queries` and mapping structs.

### 3.2. Changes to Make in Existing Files
- Add a code-generation step in the root `Makefile` / `Taskfile`: `make sqlc-generate`.
- Create a lightweight mapper between `sqlcauth.User` and `models.User`.

### 3.3. Concrete Code Blueprint (sqlc)

#### `sqlc.yaml`
```yaml
version: "2"
sql:
  - schema: "schema/schema_postgres.sql"
    queries: "queries/"
    gen:
      go:
        package: "generated"
        out: "generated"
        sql_package: "pgx/v5" # or "database/sql"
        emit_json_tags: true
        emit_pointers_for_null_types: true
```

#### SQL Query Definition (`queries/users.sql`)
```sql
-- name: CreateUser :one
INSERT INTO users (
    id, name, email, email_verified, image, role, banned,
    ban_reason, ban_expires, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
) RETURNING *;

-- name: FindUserByID :one
SELECT * FROM users
WHERE id = $1 AND deleted_at IS NULL;

-- name: FindUserByEmail :one
SELECT * FROM users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL;

-- name: SoftDeleteUser :exec
UPDATE users
SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id = $1;
```

#### Adapter Wrapper (`src/app/repository/sqlcauth/user_repo.go`)
```go
package sqlcauth

import (
    "context"
    "database/sql"
    "errors"
    "strings"

    "github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
    "github.com/better-go-auth/goauth/src/app/repository/sqlcauth/generated"
    "github.com/better-go-auth/goauth/src/common/autherr"
    "github.com/better-go-auth/goauth/src/models"
)

type UserRepo struct {
    q *generated.Queries
    db *sql.DB
}

func (r *UserRepo) CreateUser(ctx context.Context, u *models.User) (*models.User, error) {
    if u.ID == "" {
        u.ID = models.NewID()
    }
    dbUser, err := r.q.CreateUser(ctx, generated.CreateUserParams{
        ID:            u.ID,
        Name:          u.Name,
        Email:         strings.ToLower(u.Email),
        EmailVerified: u.EmailVerified,
        Image:         u.Image,
        Role:          string(u.Role),
        Banned:        u.Banned,
    })
    if err != nil {
        return nil, normalizeSQLError(err)
    }
    return toDomainUser(&dbUser), nil
}

func (r *UserRepo) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
    row, err := r.q.FindUserByEmail(ctx, strings.ToLower(email))
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, autherr.ErrNotFound
        }
        return nil, err
    }
    return toDomainUser(&row), nil
}
```

---

## 4. Implementation Plan: Standard `database/sql` & `sqlx`

Many enterprise Go systems prohibit heavyweight ORMs and code generators. Providing a native `*sql.DB` and `*sqlx.DB` adapter satisfies both needs with shared SQL logic.

### 4.1. What Needs to Be Added
1. **New Package**: `src/app/repository/stdsql/`
   - `executor.go`: `DBExecutor` interface satisfied by both `*sql.DB`, `*sql.Tx`, `*sqlx.DB`, and `*sqlx.Tx`.
   - `dialect.go`: Dynamic placeholder rebind (`?` for SQLite/MySQL, `$n` for PostgreSQL).
   - `scanner.go`: Column scanning helper for standard `database/sql` (or direct `sqlx.StructScan`).
   - `user_repo.go`, `session_repo.go`, etc.
   - `tx_manager.go`: Manages standard `sql.Tx` in context.
   - `migrator.go`: Embedded SQL migration runner.

### 4.2. Concrete Code Blueprint (`stdsql`)

#### Unified Executor Interface (`src/app/repository/stdsql/executor.go`)
```go
package stdsql

import (
    "context"
    "database/sql"
)

type DBExecutor interface {
    ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
    QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
    QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
```

#### Dynamic Rebind & Parameter Mapping (`src/app/repository/stdsql/dialect.go`)
```go
package stdsql

import (
    "fmt"
    "strconv"
    "strings"
)

type Dialect int

const (
    DialectSQLite Dialect = iota
    DialectPostgres
    DialectMySQL
)

// Rebind replaces '?' placeholders with '$1', '$2' when running on PostgreSQL.
func (d Dialect) Rebind(query string) string {
    if d != DialectPostgres {
        return query
    }
    var b strings.Builder
    idx := 1
    for i := 0; i < len(query); i++ {
        if query[i] == '?' {
            b.WriteByte('$')
            b.WriteString(strconv.Itoa(idx))
            idx++
        } else {
            b.WriteByte(query[i])
        }
    }
    return b.String()
}
```

#### Standard SQL Transaction Manager (`src/app/repository/stdsql/tx_manager.go`)
```go
package stdsql

import (
    "context"
    "database/sql"
    "github.com/better-go-auth/goauth/src/common/interfaces"
)

type StdSqlTxManager struct {
    db *sql.DB
}

func NewStdSqlTxManager(db *sql.DB) interfaces.ITransactionManager {
    return &StdSqlTxManager{db: db}
}

func (m *StdSqlTxManager) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
    if _, ok := ctx.Value(txKey).(*sql.Tx); ok {
        return fn(ctx)
    }
    tx, err := m.db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    txCtx := context.WithValue(ctx, txKey, tx)
    if err := fn(txCtx); err != nil {
        return err
    }
    return tx.Commit()
}
```

---

## 5. Implementation Plan: `Ent` (`entgo.io/ent`)

Ent is the premier graph-based ORM in Go. Ent generates entity schemas, predicates, and mutations from declarative code.

### 5.1. What Needs to Be Added
1. **Directory**: `src/app/repository/entauth/`
   - `ent/schema/`:
     - `user.go`
     - `session.go`
     - `account.go`
     - `verification.go`
     - `organization.go` (and members, teams, roles)
   - `client.go`: Wraps `*ent.Client` and transaction management.
   - `user_repo.go`, `session_repo.go`: Implements `repo_interfaces`.
   - `mapper.go`: Converts Ent generated structs (e.g. `ent.User`) to domain models (`models.User`).

### 5.2. Schema Definition Sample (`ent/schema/user.go`)
```go
package schema

import (
    "time"
    "entgo.io/ent"
    "entgo.io/ent/schema/field"
    "entgo.io/ent/schema/edge"
)

type User struct {
    ent.Schema
}

func (User) Fields() []ent.Field {
    return []ent.Field{
        field.String("id").Unique().Immutable(),
        field.String("name").Default(""),
        field.String("email").Unique(),
        field.Bool("email_verified").Default(false),
        field.String("image").Optional().Nillable(),
        field.String("role").Default("user"),
        field.Bool("banned").Default(false),
        field.Time("created_at").Default(time.Now).Immutable(),
        field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
        field.Time("deleted_at").Optional().Nillable(),
    }
}

func (User) Edges() []ent.Edge {
    return []ent.Edge{
        edge.To("sessions", Session.Type),
        edge.To("accounts", Account.Type),
    }
}
```

### 5.3. Ent User Repository (`src/app/repository/entauth/user_repo.go`)
```go
package entauth

import (
    "context"
    "strings"

    "github.com/better-go-auth/goauth/src/app/repository/entauth/ent"
    "github.com/better-go-auth/goauth/src/app/repository/entauth/ent/user"
    "github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
    "github.com/better-go-auth/goauth/src/common/autherr"
    "github.com/better-go-auth/goauth/src/models"
)

type UserRepo struct {
    client *ent.Client
}

func (r *UserRepo) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
    u, err := r.client.User.Query().
        Where(user.EmailEqualFold(strings.TrimSpace(email))).
        Where(user.DeletedAtIsNil()).
        Only(ctx)
    if err != nil {
        if ent.IsNotFound(err) {
            return nil, autherr.ErrNotFound
        }
        return nil, err
    }
    return toDomainUser(u), nil
}
```

---

## 6. Implementation Plan: Refactoring Existing `GORM` Adapter

To ensure `GORM` remains high-performing without polluting the core domain models:
1. **Isolate GORM Types**:
   - Change `models.User.DeletedAt` to `*time.Time`.
   - In `gormauth/user_repo.go`, update soft-delete queries to check `deleted_at IS NULL` or use GORM's built-in plugin tags.
2. **Move Table Naming & Dialect Fixes**:
   - Table resolution (`ResolveTableName`) is kept as a generic helper.
   - Retain `core_migration.GORMMigrator` for seamless backward compatibility.
3. **Keep Contract Test Verified**:
   - `gormauth` will continue passing 100% of the `repotest.Run(t, factory)` contract tests across SQLite, PostgreSQL, and MySQL.
