# 01: Custom Fields Design Patterns in Go

## 1. The Challenge of Schema Extensibility in Go

In TypeScript, adding an arbitrary property to an object at runtime requires zero compiler reconfiguration. In Go, struct types are fixed at compile time, field offsets are rigid, and reflection has performance implications.

When designing custom column extensibility for `better-go-auth` (`goauth`), we must balance three competing requirements:
1. **Better-Auth API Parity**: Clients expect extra fields to be top-level keys in JSON payloads (e.g., `{ "id": "...", "email": "...", "phoneNumber": "+123456" }`, NOT nested under a `{ "metadata": { ... } }` wrapper).
2. **Database Performance & Querying**: Fields like `phoneNumber` or `organizationRole` must be indexable and searchable via SQL `WHERE` clauses.
3. **Multi-ORM Portability**: The pattern must work across **GORM**, **Bun**, **`database/sql`**, **`sqlx`**, **`sqlc`**, and **`Ent`**.

---

## 2. In-Depth Evaluation of Architectural Patterns

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               ARCHITECTURAL PATTERNS COMPARISON                                 │
├────────────────────┬──────────────────┬─────────────────┬─────────────────┬─────────────────────┤
│ Pattern            │ Type Safety      │ Wire JSON Format│ DB Column Model │ Multi-ORM Difficulty│
├────────────────────┼──────────────────┼─────────────────┼─────────────────┼─────────────────────┤
│ 1. Dynamic Columns │ Runtime / Schema │ Top-Level Flat  │ Physical SQL Col│ Medium (SQL Builder)│
│ 2. JSONB Metadata  │ Runtime / Schema │ Flattened via   │ Single JSON Col │ Very Low (Native)   │
│                    │                  │ Custom JSON     │                 │                     │
│ 3. Go Generics     │ Compile-Time     │ Top-Level Flat  │ Physical SQL Col│ Extremely High      │
│    (User[T])       │                  │                 │                 │ (Viral Generics)    │
│ 4. Struct Embedding│ Compile-Time     │ Top-Level Flat  │ Physical SQL Col│ High (Requires      │
│    (AppUser)       │                  │                 │                 │ Custom Mappers)     │
└────────────────────┴──────────────────┴─────────────────┴─────────────────┴─────────────────────┘
```

---

### Pattern 1: Physical SQL Columns with Dynamic Field Map *(Better-Auth Native)*
Each declared additional field becomes a physical SQL column in the target table (e.g. `phone_number VARCHAR(255)`). The core Go entity holds an extensible map:

```go
type User struct {
    Base
    UserDto
    DeletedAt    *time.Time             `json:"deletedAt,omitempty"`
    CustomFields map[string]interface{} `json:"-"` // dynamically scanned & serialized
}
```

#### Advantages:
- **100% Better-Auth Parity**: Matches how Better Auth TypeScript functions under the hood.
- **Full Database Optimization**: You can create standard SQL B-Tree indexes, unique constraints (`UNIQUE KEY`), and foreign keys on custom columns.
- **Fast SQL Filtering**: Queries can filter directly with `WHERE phone_number = ?` rather than JSON path lookups.

#### Implementation Mechanics:
- `gormauth` and `bunauth` dynamically inject configured columns into `SELECT` statements.
- `stdsql` and `sqlx` dynamically append column names to generated query strings.

---

### Pattern 2: Single JSONB / JSON Document Column (`custom_fields`)
The table contains a dedicated `custom_fields JSONB` (Postgres) or `custom_fields JSON` (MySQL/SQLite) column. Custom fields are stored as key-value pairs inside this document.

#### Advantages:
- **Zero Schema Migrations**: New custom fields can be configured without running `ALTER TABLE`.
- **Universal ORM Support**: Works seamlessly out of the box with `sqlc`, `ent`, `gorm`, and `bun` because the column is just standard JSON.
- **No Column Explosion**: Does not alter table DDL schemas.

#### Disadvantages:
- In SQLite and older MySQL versions, indexing JSON paths requires generated virtual columns.
- Cannot easily attach foreign key constraints to properties inside a JSON document.

---

### Pattern 3: Go Generics (`User[TExtra any]`)
Why not define `type User[T any] struct { Base; UserDto; Custom T }`?

```go
type MyCustomFields struct {
    PhoneNumber string `json:"phoneNumber"`
    Tier        string `json:"tier"`
}

type AppUser = models.User[MyCustomFields]
```

#### Why Generics Fail for a Pluggable Framework:
1. **Viral Propagation**: In Go, once `User[T]` is generic, every interface and service that touches a user becomes generic:
   ```go
   type IUserRepo[TUser, TSess, TOrg any] interface { ... }
   type AuthService[TUser, TSess, TOrg any] struct { ... }
   type HumaHandler[TUser, TSess, TOrg any] struct { ... }
   ```
2. **Plugin Incompatibility**: Plugins like `org`, `admin`, `access-token`, `email-otp`, and `mfa` cannot easily be compiled or composed together if every plugin must carry 4+ generic type parameters.
3. **API Routing Constraints**: Standard HTTP routers (Chi, Gin, Echo, Huma) require non-generic handler signatures or extensive factory boilerplate.

**Verdict**: Generic entity parameters are an anti-pattern for large, multi-plugin auth engines in Go.

---

### Pattern 4: Struct Embedding with Reflection / Hooks
Developers define an extended struct that embeds `models.User`:
```go
type CustomUser struct {
    models.User
    PhoneNumber string `gorm:"column:phone_number" bun:"phone_number" json:"phoneNumber"`
}
```

The repository layer provides generic helpers to scan into custom structs when requested:
```go
user, err := authClient.GetUser(ctx, id) // returns *models.User with CustomFields map
// OR typed:
var customUser CustomUser
err := authClient.GetUserInto(ctx, id, &customUser)
```

---

## 3. The Recommended Hybrid Architecture for `goauth`

To achieve the best of all worlds, `goauth` adopts a **dual-mode extensible architecture**:

```
                                  Configuration
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
          StorageMode: "columns"                 StorageMode: "json"
     (Physical SQL Columns)                 (Single JSONB Column)
     - Full SQL Indexing                    - Zero ALTER TABLE migrations
     - Native SQL constraints               - Out-of-the-box sqlc / ent
     - Highest raw query speed              - Rapid schemaless prototyping
                    │                                       │
                    └───────────────────┬───────────────────┘
                                        ▼
                         CustomFields Type Definition
                         (Flat JSON Serialization)
```

### 3.1. The `CustomFields` Container Type
To ensure the JSON wire payload remains **flat** (matching Better-Auth specification), `models.User` and `models.Session` use a specialized container:

```go
package models

import (
    "database/sql/driver"
    "encoding/json"
)

// CustomFields stores dynamic fields declared via AdditionalFields configuration.
type CustomFields map[string]interface{}

// Value implements driver.Valuer for JSON column storage mode.
func (c CustomFields) Value() (driver.Value, error) {
    if c == nil {
        return "{}", nil
    }
    return json.Marshal(c)
}

// Scan implements sql.Scanner for JSON column storage mode.
func (c *CustomFields) Scan(src any) error {
    if src == nil {
        *c = make(CustomFields)
        return nil
    }
    var bytes []byte
    switch v := src.(type) {
    case []byte:
        bytes = v
    case string:
        bytes = []byte(v)
    default:
        *c = make(CustomFields)
        return nil
    }
    return json.Unmarshal(bytes, c)
}
```

### 3.2. Flattened JSON Serialization
When `models.User` is marshaled to JSON, `CustomFields` are flattened into top-level keys so frontend Better Auth clients receive standard responses:

```go
func (u User) MarshalJSON() ([]byte, error) {
    // 1. Marshal standard user fields
    type Alias User
    baseBytes, err := json.Marshal((*Alias)(&u))
    if err != nil {
        return nil, err
    }

    if len(u.CustomFields) == 0 {
        return baseBytes, nil
    }

    // 2. Merge custom fields into top-level JSON map
    var m map[string]interface{}
    if err := json.Unmarshal(baseBytes, &m); err != nil {
        return nil, err
    }
    for k, v := range u.CustomFields {
        m[k] = v
    }
    return json.Marshal(m)
}
```
Resulting Wire Output:
```json
{
  "id": "usr_99x811a",
  "name": "Alice Developer",
  "email": "alice@example.com",
  "emailVerified": true,
  "phoneNumber": "+1234567890",
  "loyaltyTier": "gold"
}
```
This guarantees **100% client-side drop-in compatibility** with existing Better Auth SDKs (`@better-auth/client`, React, Vue, Svelte)!
