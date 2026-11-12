# 05: Physical Columns Migration Engine

## 1. Overview of Physical Column Migrations

When using physical column storage, every declared additional field in `AdditionalFields` maps directly to a **real, native column** in the target SQL database table (e.g. `users`, `sessions`, `organizations`):

```
Go Configuration (AdditionalFields)
┌──────────────────────────────────────────────┐
│ "phoneNumber": { Type: "string", Unique: true}│
│ "age":         { Type: "number", Index: true }│
│ "isVerified":  { Type: "boolean" }            │
└──────────────────────┬───────────────────────┘
                       │ Introspection & DDL Generator
                       ▼
Database Table Schema Evolution
┌────────────────────────────────────────────────────────────────────────┐
│ ALTER TABLE users ADD COLUMN phone_number VARCHAR(255);                │
│ CREATE UNIQUE INDEX uq_users_phone_number ON users(phone_number);      │
│ ALTER TABLE users ADD COLUMN age DOUBLE;                               │
│ CREATE INDEX idx_users_age ON users(age);                              │
│ ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;        │
└────────────────────────────────────────────────────────────────────────┘
```

This document details how the migration engine discovers existing table structures, generates dialect-safe DDL, handles constraints on existing rows, and executes zero-downtime migrations.

---

## 2. Dynamic Schema Introspection

Before generating any DDL, the migration engine queries the database metadata catalog to inspect the existing columns of the target table.

```
                           Target Table: "users"
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
       Inspect Existing Columns                Inspect Existing Indexes
   (Name, Type, Nullable, Default)         (Index Name, Column, Unique)
                 │                                       │
                 └───────────────────┬───────────────────┘
                                     │
                                     ▼
                     Diff Against `AdditionalFields`
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
           Column Exists                           Column Missing
        (Verify/Skip DDL)                                │
                                                         ▼
                                               Generate & Execute DDL
```

### 2.1. PostgreSQL Column & Index Introspection
In PostgreSQL, column and index metadata are read from `information_schema` and `pg_catalog`:

```go
package migration

import (
    "context"
    "database/sql"
    "fmt"
    "strings"
)

type ColumnMeta struct {
    Name       string
    DataType   string
    IsNullable bool
    DefaultVal *string
}

func (m *PostgresMigrator) GetExistingColumns(ctx context.Context, table string) (map[string]ColumnMeta, error) {
    query := `
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = $1;
    `
    rows, err := m.db.QueryContext(ctx, query, table)
    if err != nil {
        return nil, fmt.Errorf("postgres/inspect: query columns: %w", err)
    }
    defer rows.Close()

    cols := make(map[string]ColumnMeta)
    for rows.Next() {
        var col ColumnMeta
        var nullable string
        var defVal sql.NullString
        if err := rows.Scan(&col.Name, &col.DataType, &nullable, &defVal); err != nil {
            return nil, err
        }
        col.IsNullable = strings.ToUpper(nullable) == "YES"
        if defVal.Valid {
            col.DefaultVal = &defVal.String
        }
        cols[strings.ToLower(col.Name)] = col
    }
    return cols, nil
}
```

### 2.2. MySQL 8.0+ Column & Index Introspection
In MySQL, indexed varchar columns must specify a character length (to avoid InnoDB Error 1170):

```go
func (m *MySQLMigrator) GetExistingColumns(ctx context.Context, table string) (map[string]ColumnMeta, error) {
    query := `
        SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?;
    `
    rows, err := m.db.QueryContext(ctx, query, table)
    if err != nil {
        return nil, fmt.Errorf("mysql/inspect: query columns: %w", err)
    }
    defer rows.Close()

    cols := make(map[string]ColumnMeta)
    for rows.Next() {
        var col ColumnMeta
        var nullable string
        var defVal sql.NullString
        if err := rows.Scan(&col.Name, &col.DataType, &nullable, &defVal); err != nil {
            return nil, err
        }
        col.IsNullable = strings.ToUpper(nullable) == "YES"
        if defVal.Valid {
            col.DefaultVal = &defVal.String
        }
        cols[strings.ToLower(col.Name)] = col
    }
    return cols, nil
}
```

### 2.3. SQLite 3 Column Introspection
In SQLite, metadata is retrieved via the `PRAGMA table_info` command:

```go
func (m *SQLiteMigrator) GetExistingColumns(ctx context.Context, table string) (map[string]ColumnMeta, error) {
    query := fmt.Sprintf("PRAGMA table_info(%s);", table)
    rows, err := m.db.QueryContext(ctx, query)
    if err != nil {
        return nil, fmt.Errorf("sqlite/inspect: pragma table_info: %w", err)
    }
    defer rows.Close()

    cols := make(map[string]ColumnMeta)
    for rows.Next() {
        var cid, notnull, pk int
        var name, ctype string
        var dflt sql.NullString
        if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
            return nil, err
        }
        cols[strings.ToLower(name)] = ColumnMeta{
            Name:       name,
            DataType:   ctype,
            IsNullable: notnull == 0,
        }
    }
    return cols, nil
}
```

---

## 3. Dialect DDL Generation

When a configured field is missing from the database, the migrator builds the dialect-specific SQL statement:

```go
type FieldConfig struct {
    Type       FieldType // "string", "number", "boolean", "date", "json"
    Required   bool
    Default    any
    Unique     bool
    Index      bool
    ColumnName string
}
```

### 3.1. DDL Construction by Database Engine

```go
func GenerateAddColumnSQL(dialect Dialect, table, colName string, cfg FieldConfig) (string, []string) {
    var colType string
    var defaultClause string
    var extraStatements []string

    switch cfg.Type {
    case FieldTypeString:
        switch dialect {
        case DialectPostgres:
            colType = "VARCHAR(255)"
        case DialectMySQL:
            colType = "VARCHAR(255)"
        case DialectSQLite:
            colType = "TEXT"
        }

    case FieldTypeNumber:
        switch dialect {
        case DialectPostgres:
            colType = "DOUBLE PRECISION"
        case DialectMySQL:
            colType = "DOUBLE"
        case DialectSQLite:
            colType = "REAL"
        }

    case FieldTypeBoolean:
        switch dialect {
        case DialectPostgres:
            colType = "BOOLEAN"
            defaultClause = " DEFAULT FALSE"
        case DialectMySQL:
            colType = "TINYINT(1)"
            defaultClause = " DEFAULT 0"
        case DialectSQLite:
            colType = "INTEGER"
            defaultClause = " DEFAULT 0"
        }

    case FieldTypeDate:
        switch dialect {
        case DialectPostgres:
            colType = "TIMESTAMPTZ"
        case DialectMySQL:
            colType = "DATETIME(6)"
        case DialectSQLite:
            colType = "DATETIME"
        }

    case FieldTypeJSON:
        switch dialect {
        case DialectPostgres:
            colType = "JSONB"
            defaultClause = " DEFAULT '{}'::jsonb"
        case DialectMySQL:
            colType = "JSON"
        case DialectSQLite:
            colType = "TEXT"
            defaultClause = " DEFAULT '{}'"
        }
    }

    // Default value formatting
    if cfg.Default != nil {
        switch v := cfg.Default.(type) {
        case string:
            defaultClause = fmt.Sprintf(" DEFAULT '%s'", escapeSQLString(v))
        case bool:
            if v {
                if dialect == DialectPostgres {
                    defaultClause = " DEFAULT TRUE"
                } else {
                    defaultClause = " DEFAULT 1"
                }
            } else {
                if dialect == DialectPostgres {
                    defaultClause = " DEFAULT FALSE"
                } else {
                    defaultClause = " DEFAULT 0"
                }
            }
        case int, int64, float64:
            defaultClause = fmt.Sprintf(" DEFAULT %v", v)
        }
    }

    // Nullability:
    // IMPORTANT: When adding columns to an existing table with existing rows,
    // a NOT NULL constraint without a DEFAULT value will fail!
    nullClause := ""
    if cfg.Required && defaultClause != "" {
        nullClause = " NOT NULL"
    }

    // Main ALTER TABLE statement
    var mainSQL string
    switch dialect {
    case DialectPostgres:
        mainSQL = fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s%s%s;", table, colName, colType, defaultClause, nullClause)
    case DialectMySQL:
        mainSQL = fmt.Sprintf("ALTER TABLE `%s` ADD COLUMN `%s` %s%s%s;", table, colName, colType, defaultClause, nullClause)
    case DialectSQLite:
        mainSQL = fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s%s%s;", table, colName, colType, defaultClause, nullClause)
    }

    // Secondary statements: Indexes and Unique Constraints
    idxName := fmt.Sprintf("idx_%s_%s", table, colName)
    uqName := fmt.Sprintf("uq_%s_%s", table, colName)

    if cfg.Unique {
        switch dialect {
        case DialectPostgres:
            extraStatements = append(extraStatements, fmt.Sprintf("CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s(%s);", uqName, table, colName))
        case DialectMySQL:
            extraStatements = append(extraStatements, fmt.Sprintf("ALTER TABLE `%s` ADD UNIQUE KEY `%s` (`%s`);", table, uqName, colName))
        case DialectSQLite:
            extraStatements = append(extraStatements, fmt.Sprintf("CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s(%s);", uqName, table, colName))
        }
    } else if cfg.Index {
        switch dialect {
        case DialectPostgres:
            extraStatements = append(extraStatements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s);", idxName, table, colName))
        case DialectMySQL:
            extraStatements = append(extraStatements, fmt.Sprintf("ALTER TABLE `%s` ADD KEY `%s` (`%s`);", table, idxName, colName))
        case DialectSQLite:
            extraStatements = append(extraStatements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s);", idxName, table, colName))
        }
    }

    return mainSQL, extraStatements
}
```

---

## 4. Handling Critical Edge Cases

### 4.1. Adding NOT NULL Columns to Non-Empty Tables
If the `users` table already contains 10,000 users, executing `ALTER TABLE users ADD COLUMN phone_number VARCHAR(255) NOT NULL;` will fail in PostgreSQL, MySQL, and SQLite because existing rows have `NULL`.

**Engine Solution**:
1. If `Required: true` but `Default == nil`, the engine creates the column as **nullable** in the database DDL, but enforces `Required` at the Go application validation layer for all subsequent `POST /sign-up/email` and `POST /update-user` requests!
2. If `Required: true` and `Default != nil`, the DDL includes `DEFAULT <val> NOT NULL`, allowing existing rows to populate with the fallback value safely.

### 4.2. Adding UNIQUE Constraints to Existing Data
In relational databases, multiple rows with `NULL` are valid under unique constraints in PostgreSQL and SQLite, but MySQL handles NULLs differently depending on collation.

**Engine Solution**:
The engine uses **partial unique indexes** on PostgreSQL and SQLite when the column is nullable:
```sql
-- PostgreSQL: only enforce uniqueness for non-null values
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_phone_number ON users(phone_number) WHERE phone_number IS NOT NULL;
```
For MySQL:
```sql
-- In MySQL, multiple NULL values are permitted in UNIQUE keys by default (InnoDB standard)
ALTER TABLE `users` ADD UNIQUE KEY `uq_users_phone_number` (`phone_number`);
```

---

## 5. Migration Execution Flow in `IMigrator`

The complete execution sequence inside `Migrate(ctx context.Context)`:

```go
func (m *PhysicalColumnMigrator) Migrate(ctx context.Context) error {
    // 1. Run base core migrations first (creates users, sessions, accounts, verifications)
    if err := m.baseMigrator.Migrate(ctx); err != nil {
        return fmt.Errorf("base migration: %w", err)
    }

    // 2. Resolve tables that have additional fields configured
    tableConfigs := map[string]map[string]FieldConfig{
        "users":    m.userAdditionalFields,
        "sessions": m.sessionAdditionalFields,
        // orgs, teams, etc.
    }

    for tableName, fields := range tableConfigs {
        if len(fields) == 0 {
            continue
        }

        // 3. Inspect existing columns
        existingCols, err := m.inspector.GetExistingColumns(ctx, tableName)
        if err != nil {
            return fmt.Errorf("inspect table %s: %w", tableName, err)
        }

        // 4. Migrate missing columns
        for fieldName, fieldCfg := range fields {
            colName := resolveColumnName(fieldName, fieldCfg.ColumnName)
            if _, exists := existingCols[strings.ToLower(colName)]; exists {
                continue // Already migrated
            }

            mainDDL, extraDDLs := GenerateAddColumnSQL(m.dialect, tableName, colName, fieldCfg)

            // Execute main ALTER TABLE
            if _, err := m.db.ExecContext(ctx, mainDDL); err != nil {
                return fmt.Errorf("executing DDL '%s': %w", mainDDL, err)
            }

            // Execute indexes / constraints
            for _, extraDDL := range extraDDLs {
                if _, err := m.db.ExecContext(ctx, extraDDL); err != nil {
                    return fmt.Errorf("executing index DDL '%s': %w", extraDDL, err)
                }
            }
        }
    }

    return nil
}
```
This guarantees that any newly configured custom field is automatically converted into a physical SQL column on application start with zero manual intervention.
