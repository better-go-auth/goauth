# 04: Dynamic Migrations & DDL Evolution

## 1. Automated Schema Evolution for Custom Columns

When a developer declares new fields in `AdditionalFields`:
```go
User: goauth.UserConfig{
    AdditionalFields: map[string]goauth.FieldConfig{
        "phoneNumber": { Type: goauth.FieldTypeString, Unique: true },
        "department":  { Type: goauth.FieldTypeString, Index: true },
    },
}
```

The database schema must evolve cleanly. In `goauth`, schema evolution operates in two modes:
1. **Auto-Migration on Startup (`AutoMigrate: true`)**: The `IMigrator` checks existing table columns and executes idempotent `ALTER TABLE` statements for any newly declared fields.
2. **CLI / Raw SQL Generation**: A CLI tool (`go run cmd/goauth migrate --dry-run`) generates standard SQL migration files (`.sql`) for CI/CD pipelines (e.g. Flyway, Goose, Atlas, Golang-Migrate).

---

## 2. Dialect Column Type Mapping Matrix

Different database engines enforce different type rules and syntax constraints. The migration engine maps `FieldConfig` types to native DDL:

| FieldType | PostgreSQL | MySQL 8.0+ | SQLite 3 |
| :--- | :--- | :--- | :--- |
| **`string` (unindexed)** | `TEXT` | `VARCHAR(255)` | `TEXT` |
| **`string` (indexed/unique)**| `VARCHAR(255)` | `VARCHAR(255)` | `TEXT` |
| **`number` (integer)** | `BIGINT` | `BIGINT` | `INTEGER` |
| **`number` (float)** | `DOUBLE PRECISION` | `DOUBLE` | `REAL` |
| **`boolean`** | `BOOLEAN DEFAULT FALSE`| `TINYINT(1) DEFAULT 0`| `INTEGER DEFAULT 0` |
| **`date`** | `TIMESTAMPTZ` | `DATETIME(6)` | `DATETIME` |
| **`json`** | `JSONB DEFAULT '{}'::jsonb`| `JSON` | `TEXT DEFAULT '{}'` |

---

## 3. Idempotent DDL Execution Engine

Running `ALTER TABLE` must be safe for repeated execution without throwing "duplicate column" errors.

```
                  Inspect Existing Table Schema
                 (Postgres / MySQL / SQLite Catalog)
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
     Column Already Exists               Column Missing
         (Skip DDL)                               │
                                                  ▼
                                       Generate ALTER TABLE DDL
                                                  │
                                                  ▼
                                      Create Optional B-Tree Index
```

### 3.1. PostgreSQL DDL Execution
PostgreSQL 9.6+ natively supports `ADD COLUMN IF NOT EXISTS`:
```sql
-- Add column
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(255);

-- Create index if specified
CREATE INDEX IF NOT EXISTS idx_users_phone_number ON users(phone_number);

-- Create unique index if specified
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_phone_number ON users(phone_number);
```

### 3.2. MySQL 8.0+ DDL Execution
MySQL does not support `IF NOT EXISTS` on `ALTER TABLE ADD COLUMN`. The migrator inspects `information_schema`:
```go
func (m *MySQLMigrator) AddColumnIfNotExists(ctx context.Context, table, col, colType string) error {
    var count int
    checkQuery := `
        SELECT COUNT(*) FROM information_schema.columns 
        WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?;
    `
    if err := m.db.QueryRowContext(ctx, checkQuery, table, col).Scan(&count); err != nil {
        return err
    }
    if count > 0 {
        return nil // Column already present
    }

    alterSQL := fmt.Sprintf("ALTER TABLE `%s` ADD COLUMN `%s` %s", table, col, colType)
    _, err := m.db.ExecContext(ctx, alterSQL)
    return err
}
```

### 3.3. SQLite 3 DDL Execution
SQLite inspects `PRAGMA table_info`:
```go
func (m *SQLiteMigrator) AddColumnIfNotExists(ctx context.Context, table, col, colType string) error {
    rows, err := m.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
    if err != nil {
        return err
    }
    defer rows.Close()

    for rows.Next() {
        var cid int
        var name, ctype string
        var notnull, pk int
        var dflt any
        if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err == nil {
            if strings.EqualFold(name, col) {
                return nil // Column already present
            }
        }
    }

    alterSQL := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, col, colType)
    _, err = m.db.ExecContext(ctx, alterSQL)
    return err
}
```

---

## 4. Universal Migration Interface Implementation (`IMigrator`)

In Phase 7, all adapters implemented the unified `migration.IMigrator`:
```go
type IMigrator interface {
    Migrate(ctx context.Context) error
}
```

In Phase 8, `NewMigrator` accepts the additional fields configuration and applies the dynamic schema updates alongside the base schema:

```go
package core_migration

type AutoMigrator struct {
    db               DBExecutor
    dialect          Dialect
    additionalFields map[string]FieldConfig
}

func (m *AutoMigrator) Migrate(ctx context.Context) error {
    // 1. Run core table migrations (users, sessions, accounts, verifications)
    if err := m.migrateCoreTables(ctx); err != nil {
        return fmt.Errorf("core migration: %w", err)
    }

    // 2. Run dynamic column migrations for configured additional fields
    for fieldName, cfg := range m.additionalFields {
        colName := resolveColumnName(fieldName, cfg.ColumnName)
        colType := m.dialect.MapType(cfg)

        if err := m.addColumnIfNotExists(ctx, "users", colName, colType); err != nil {
            return fmt.Errorf("migrate column %s: %w", colName, err)
        }

        if cfg.Index {
            if err := m.createIndexIfNotExists(ctx, "users", colName, cfg.Unique); err != nil {
                return fmt.Errorf("create index on %s: %w", colName, err)
            }
        }
    }

    return nil
}
```

---

## 5. Automated Verification with Testcontainers

To ensure complete reliability across all environments, dynamic migrations and custom column operations are validated across SQLite, PostgreSQL, and MySQL using the test helpers from Phase 6/7:

```go
func TestDynamicColumnMigration(t *testing.T) {
    helpers.RunForEachDB(t, func(t *testing.T, dbType string) {
        testDB := helpers.SetupTestDB(t, dbType)

        // 1. Configure custom fields
        customFields := map[string]goauth.FieldConfig{
            "phoneNumber": {Type: goauth.FieldTypeString, Unique: true, Index: true},
            "age":         {Type: goauth.FieldTypeNumber},
        }

        // 2. Run dynamic migrations
        migrator := core_migration.NewAutoMigrator(testDB.DB, helpers.GetDialect(dbType), customFields)
        require.NoError(t, migrator.Migrate(context.Background()))

        // 3. Verify user creation with custom columns
        userRepo := gormauth.NewUserRepoWithFields(testDB.DB, customFields)
        u, err := userRepo.CreateUser(context.Background(), &models.User{
            UserDto: models.UserDto{Name: "Bob", Email: "bob@example.com"},
            CustomFields: map[string]any{
                "phoneNumber": "+1-555-0199",
                "age":         30,
            },
        })
        require.NoError(t, err)

        // 4. Verify round-trip retrieval
        found, err := userRepo.FindUserByID(context.Background(), u.ID)
        require.NoError(t, err)
        require.Equal(t, "+1-555-0199", found.CustomFields["phoneNumber"])
        require.Equal(t, float64(30), found.CustomFields["age"])
    })
}
```
This guarantees that custom columns seamlessly evolve in production databases with zero manual SQL intervention!
