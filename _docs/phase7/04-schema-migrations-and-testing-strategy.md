# 04: Schema Migrations & Universal Testing Strategy

## 1. Dialect-Specific Schema Specifications

To guarantee identical behavior across all ORMs and SQL toolkits, `goauth` must maintain canonical DDL schemas for the three supported database engines: **PostgreSQL**, **MySQL**, and **SQLite**.

### 1.1. PostgreSQL DDL (`schema/postgres.sql`)
```sql
-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL DEFAULT '',
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    image TEXT,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    ban_reason TEXT,
    ban_expires TIMESTAMPTZ,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    username VARCHAR(100),
    display_name VARCHAR(255),
    bio TEXT,
    date_of_birth TIMESTAMPTZ,
    gender VARCHAR(50),
    locale VARCHAR(20) DEFAULT 'en',
    timezone VARCHAR(50),
    last_login_ip VARCHAR(45),
    last_login_at TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users(LOWER(email));

-- 2. Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    token VARCHAR(255) NOT NULL UNIQUE,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    impersonated_by VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    active_organization_id VARCHAR(36),
    active_team_id VARCHAR(36),
    active_organization_role VARCHAR(50),
    device_token VARCHAR(255),
    device_id VARCHAR(255),
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- 3. Accounts Table (OAuth & Credentials)
CREATE TABLE IF NOT EXISTS accounts (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id VARCHAR(255) NOT NULL,
    provider_id VARCHAR(50) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    access_token_expires_at TIMESTAMPTZ,
    refresh_token_expires_at TIMESTAMPTZ,
    scope TEXT,
    id_token TEXT,
    password TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_accounts_provider_account UNIQUE (provider_id, account_id)
);
CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);

-- 4. Verifications Table
CREATE TABLE IF NOT EXISTS verifications (
    id VARCHAR(36) PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_verifications_identifier ON verifications(identifier);

-- 5. Organization Roles Table (Dynamic RBAC)
CREATE TABLE IF NOT EXISTS organization_roles (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    role VARCHAR(100) NOT NULL,
    permission JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_org_roles_org_role UNIQUE (organization_id, role)
);
```

---

### 1.2. MySQL 8.0+ DDL (`schema/mysql.sql`)
*Key difference: MySQL requires explicit lengths on indexed columns to avoid Error 1170 (`BLOB/TEXT column used in key specification without a key length`).*
```sql
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL DEFAULT '',
    email VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    image TEXT,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    ban_reason TEXT,
    ban_expires DATETIME(6),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    username VARCHAR(100),
    display_name VARCHAR(255),
    bio TEXT,
    date_of_birth DATETIME(6),
    gender VARCHAR(50),
    locale VARCHAR(20) DEFAULT 'en',
    timezone VARCHAR(50),
    last_login_ip VARCHAR(45),
    last_login_at DATETIME(6),
    last_seen DATETIME(6),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    deleted_at DATETIME(6),
    UNIQUE KEY uq_users_email (email),
    KEY idx_users_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    token VARCHAR(255) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    impersonated_by VARCHAR(255),
    active_organization_id VARCHAR(255),
    active_team_id VARCHAR(255),
    active_organization_role VARCHAR(50),
    device_token VARCHAR(255),
    device_id VARCHAR(255),
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    last_used_at DATETIME(6),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_sessions_token (token),
    KEY idx_sessions_user_id (user_id),
    KEY idx_sessions_expires_at (expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS organization_roles (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(100) NOT NULL,
    role VARCHAR(100) NOT NULL,
    permission JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_org_role (organization_id, role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

---

### 1.3. SQLite DDL (`schema/sqlite.sql`)
```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    email_verified INTEGER NOT NULL DEFAULT 0,
    image TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    banned INTEGER NOT NULL DEFAULT 0,
    ban_reason TEXT,
    ban_expires DATETIME,
    first_name TEXT,
    last_name TEXT,
    username TEXT,
    display_name TEXT,
    bio TEXT,
    date_of_birth DATETIME,
    gender TEXT,
    locale TEXT DEFAULT 'en',
    timezone TEXT,
    last_login_ip TEXT,
    last_login_at DATETIME,
    last_seen DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);

CREATE TABLE IF NOT EXISTS organization_roles (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    role TEXT NOT NULL,
    permission TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(organization_id, role)
);
```

---

## 2. Universal Contract Testing Strategy

To guarantee that any new adapter (`bunauth`, `sqlcauth`, `stdsql`, `entauth`) behaves identically to `gormauth`, all adapters must execute and pass the existing contract test suite:
`github.com/better-go-auth/goauth/src/app/repository/repotest`

### 2.1. Contract Invariants Tested by `repotest.Run`
1. **User Invariants**:
   - Case-insensitive email retrieval: `FindUserByEmail("ALICE@EXAMPLE.COM")` matches user created with `alice@example.com`.
   - Unique email constraint: duplicate email creation returns an error.
   - Soft-delete behavior: `DeleteUser(id)` soft-deletes the record; subsequent `FindUserByID` and `FindUserByEmail` return `autherr.ErrNotFound`.
   - Partial updates: `UpdateUser(id, map[string]any{"EmailVerified": true})` correctly mutates single columns without zeroing out others.
2. **Session Invariants**:
   - Token uniqueness and exact match lookup.
   - Cascading user deletion: Deleting a user cleans up all attached sessions.
   - UTC timestamp consistency on `ExpiresAt`.
   - Batch deletion: `DeleteExpiredSessions()` deletes all sessions where `ExpiresAt < time.Now()`.
3. **Verification Invariants**:
   - Atomic consumption (`ConsumeVerificationValue`): Under high concurrency, only one process succeeds; all others receive `autherr.ErrNotFound`.
   - Upsert semantics (`UpsertVerificationValue`): Existing identifier is replaced in-place.
4. **Transaction Invariants**:
   - Atomic rollback: If any step within `ITransactionManager.Transaction` returns an error, zero mutations persist.
   - Context nesting: Nested `Transaction` calls participate in the parent transaction without deadlocking.

### 2.2. Multi-Database Test Automation with Testcontainers
Using the test helper established in `src/tests/helpers/db_testcontainers.go`, every adapter test runs automatically across all three database engines:

```go
package bunauth_test

import (
    "testing"
    "github.com/better-go-auth/goauth/src/app/repository/bunauth"
    "github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
    "github.com/better-go-auth/goauth/src/app/repository/repotest"
    "github.com/better-go-auth/goauth/src/tests/helpers"
    "github.com/uptrace/bun"
)

func TestBunRepositoryContract(t *testing.T) {
    helpers.RunForEachDB(t, func(t *testing.T, dbType string) {
        testDB := helpers.SetupTestDB(t, dbType)
        sqlDB, err := testDB.DB.DB()
        require.NoError(t, err)

        bunDB := bun.NewDB(sqlDB, helpers.GetBunDialect(dbType))
        defer bunDB.Close()

        repotest.Run(t, func(t *testing.T) repo_interfaces.IAuthRepos {
            return bunauth.NewAuthRepos(bunDB)
        })
    })
}
```

---

## 3. Phased Implementation Roadmap

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                          PHASE 7 IMPLEMENTATION ROADMAP                          │
├─────────┬───────────────────────────────┬────────────────────────────────────────┤
│ Step 1  │ Domain Model Neutralization   │ Replace `gorm.DeletedAt` with `*Time`  │
│         │                               │ Remove ORM imports from `src/models/`  │
├─────────┼───────────────────────────────┼────────────────────────────────────────┤
│ Step 2  │ Canonical SQL DDL & Migrator  │ Add `migrations/` embedded SQL scripts │
│         │                               │ Create `stdsql.Migrator`               │
├─────────┼───────────────────────────────┼────────────────────────────────────────┤
│ Step 3  │ Bun Adapter (`bunauth`)       │ Implement Bun repos & verify contract  │
│         │                               │ 100% tests pass on SQLite, PG, MySQL   │
├─────────┼───────────────────────────────┼────────────────────────────────────────┤
│ Step 4  │ Standard `database/sql` / sqlx│ Implement `stdsql` executor & repos    │
│         │                               │ Verify contract test suite             │
├─────────┼───────────────────────────────┼────────────────────────────────────────┤
│ Step 5  │ `sqlc` Adapter (`sqlcauth`)   │ Add `sqlc.yaml`, generate Go code,     │
│         │                               │ Implement mapper & verify contract     │
├─────────┼───────────────────────────────┼────────────────────────────────────────┤
│ Step 6  │ `Ent` Adapter (`entauth`)     │ Add Ent schema, generate client,       │
│         │                               │ Implement mapper & verify contract     │
└─────────┴───────────────────────────────┴────────────────────────────────────────┘
```

By completing this roadmap, `better-go-auth` achieves true database agnosticism, making it the most flexible and production-ready authentication engine in the Go ecosystem.
