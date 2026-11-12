# 07: Physical Columns Code Changes & Implementation Guide

## 1. Overview of Required Changes

To implement physical custom columns across `better-go-auth` (`goauth`), changes must be made across 5 layers:
1. **Model Layer (`src/models/`)**: Add `CustomFields` container with flattened JSON marshaling.
2. **DTO & API Layer (`src/models/dtos/`, `src/app/adapters/huma/`)**: Accept extra input fields in request bodies and include them in response payloads.
3. **Validation & Security Layer (`src/common/validation/`)**: Whitelist fields, enforce `input: false` protection, coerce types.
4. **Migration Layer (`src/models/migration/`)**: Introspect database tables and execute `ALTER TABLE ... ADD COLUMN` statements.
5. **Repository Layer (`src/app/repository/`)**: Modify `gormauth`, `bunauth`, and `stdsql` adapters to select, insert, and update physical columns.

---

## 2. File-by-File Blueprint

### Summary Matrix
| File Path | Action | Description |
| :--- | :---: | :--- |
| `src/models/custom_fields.go` | **ADD** | Define `CustomFields` container type, `FieldConfig`, `FieldType`, and JSON flattening. |
| `src/models/auth.user.go` | **MODIFY** | Add `CustomFields CustomFields` to `models.User` struct. |
| `src/models/auth.session.go` | **MODIFY** | Add `CustomFields CustomFields` to `models.Session` struct. |
| `src/models/dtos/better_auth.go` | **MODIFY** | Flatten `CustomFields` into `UserResponse` and `SessionData`. |
| `src/common/validation/custom_fields.go` | **ADD** | Security sanitization, mass-assignment guard, type coercion. |
| `src/models/migration/physical_migrator.go`| **ADD** | Schema introspection & DDL generator for Postgres, MySQL, SQLite. |
| `src/app/repository/gormauth/user_repo.go` | **MODIFY** | Insert/Query/Update physical columns via dynamic maps. |
| `src/app/repository/gormauth/session_repo.go`| **MODIFY**| Dynamic physical column support on sessions. |
| `src/app/services/auth/service.go` | **MODIFY** | Validate custom fields on `SignUpEmail` and `UpdateUser`. |
| `src/app/adapters/huma/auth_routes.go` | **MODIFY** | Extract dynamic body properties into `CustomFields`. |

---

## 3. Concrete Code Changes

### 3.1. Create `src/models/custom_fields.go`
```go
package models

import (
    "encoding/json"
    "fmt"
)

type FieldType string

const (
    FieldTypeString  FieldType = "string"
    FieldTypeNumber  FieldType = "number"
    FieldTypeBoolean FieldType = "boolean"
    FieldTypeDate    FieldType = "date"
    FieldTypeJSON    FieldType = "json"
)

type FieldConfig struct {
    Type       FieldType           `json:"type"`
    Required   bool                `json:"required,omitempty"`
    Default    any                 `json:"defaultValue,omitempty"`
    Input      *bool               `json:"input,omitempty"`    // Default: true
    Returned   *bool               `json:"returned,omitempty"` // Default: true
    Unique     bool                `json:"unique,omitempty"`
    Index      bool                `json:"index,omitempty"`
    ColumnName string              `json:"columnName,omitempty"`
    Validator  func(val any) error `json:"-"`
}

func (f FieldConfig) CanInput() bool {
    if f.Input == nil { return true }
    return *f.Input
}

func (f FieldConfig) IsReturned() bool {
    if f.Returned == nil { return true }
    return *f.Returned
}

// CustomFields stores dynamic physical column values.
type CustomFields map[string]interface{}
```

---

### 3.2. Update `src/models/auth.user.go`
Add `CustomFields` to `models.User` and implement flattened `MarshalJSON()`:

```go
type User struct {
    Base         `mapstructure:",squash"`
    UserDto      `mapstructure:",squash"`
    LastSeen     *time.Time             `json:"last_seen,omitempty"`
    DeletedAt    *time.Time             `json:"deletedAt,omitempty" gorm:"index" bun:"deleted_at,soft_delete"`
    Sessions     []Session              `json:"sessions,omitempty"  gorm:"foreignKey:UserID"`
    Tokens       []string               `json:"tokens,omitempty"    gorm:"-"`
    CustomFields CustomFields           `json:"-"                   gorm:"-" bun:"-"` // Physical columns
}

// MarshalJSON merges custom physical columns into top-level JSON keys for Better Auth client parity.
func (u User) MarshalJSON() ([]byte, error) {
    type Alias User
    raw, err := json.Marshal((*Alias)(&u))
    if err != nil {
        return nil, err
    }
    if len(u.CustomFields) == 0 {
        return raw, nil
    }

    var m map[string]interface{}
    if err := json.Unmarshal(raw, &m); err != nil {
        return nil, err
    }
    for k, v := range u.CustomFields {
        m[k] = v
    }
    return json.Marshal(m)
}
```

---

### 3.3. Create Validation Engine: `src/common/validation/custom_fields.go`
```go
package validation

import (
    "fmt"
    "time"
    "github.com/better-go-auth/goauth/src/common/autherr"
    "github.com/better-go-auth/goauth/src/models"
)

func SanitizeCustomFields(
    raw map[string]interface{},
    schema map[string]models.FieldConfig,
    isUpdate bool,
) (models.CustomFields, error) {
    clean := make(models.CustomFields)

    for name, cfg := range schema {
        val, exists := raw[name]

        // Guard against mass-assignment
        if exists && !cfg.CanInput() {
            return nil, fmt.Errorf("%w: field '%s' cannot be modified by user", autherr.ErrInvalidInput, name)
        }

        if !exists || val == nil {
            if cfg.Required && !isUpdate {
                if cfg.Default != nil {
                    clean[name] = cfg.Default
                } else {
                    return nil, fmt.Errorf("%w: missing required field '%s'", autherr.ErrInvalidInput, name)
                }
            } else if cfg.Default != nil && !isUpdate {
                clean[name] = cfg.Default
            }
            continue
        }

        // Validate type
        coerced, err := coerceType(name, val, cfg.Type)
        if err != nil {
            return nil, err
        }

        // Custom validation hook
        if cfg.Validator != nil {
            if err := cfg.Validator(coerced); err != nil {
                return nil, fmt.Errorf("%w: invalid field '%s': %v", autherr.ErrInvalidInput, name, err)
            }
        }

        clean[name] = coerced
    }

    return clean, nil
}
```

---

### 3.4. Update Huma Route Ingestion (`src/app/adapters/huma/auth_routes.go`)
Huma unmarshals request bodies into `dtos.SignUpEmailInput`. To capture additional fields without rejecting unknown JSON properties:

```go
type signUpInput struct {
    Body struct {
        dtos.SignUpEmailInput
        RawExtra map[string]interface{} `json:"-" additionalProperties:"true"`
    }
}

func (h *handler) SignUpEmail(ctx context.Context, in *signUpInput) (*signUpOutput, error) {
    // 1. Sanitize additional fields against configured schema
    customFields, err := validation.SanitizeCustomFields(in.Body.RawExtra, h.Config.User.AdditionalFields, false)
    if err != nil {
        return nil, err
    }

    // 2. Attach to input DTO
    in.Body.SignUpEmailInput.CustomFields = customFields

    // 3. Delegate to AuthService
    res, err := h.Auth.SignUpEmail(ctx, in.Body.SignUpEmailInput, h.meta(ctx))
    if err != nil {
        return nil, err
    }
    // ...
}
```

---

### 3.5. Update `src/app/repository/gormauth/user_repo.go`
Modify `CreateUser`, `FindUserByID`, and `UpdateUser` to map physical columns:

```go
func (r *UserRepo) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
    if user.ID == "" {
        user.ID = models.NewID()
    }
    user.Email = strings.ToLower(strings.TrimSpace(user.Email))

    // 1. Build row dictionary
    row := map[string]interface{}{
        "id":             user.ID,
        "name":           user.Name,
        "email":          user.Email,
        "email_verified": user.EmailVerified,
        "image":          user.Image,
        "role":           string(user.Role),
        "banned":         user.Banned,
        "created_at":     time.Now().UTC(),
        "updated_at":     time.Now().UTC(),
    }

    // 2. Append configured physical columns
    for fieldName, val := range user.CustomFields {
        colName := r.fieldToColMap[fieldName]
        row[colName] = val
    }

    // 3. Insert row
    db := gormutil.GetDB(ctx, r.db)
    if err := db.Table("users").Create(row).Error; err != nil {
        return nil, normalizeGormError(err)
    }

    return user, nil
}
```

---

## 4. Verification Checklist

When adding physical columns support, verify the following test scenarios:
- [ ] **Column Discovery**: System introspects existing table without executing redundant `ALTER TABLE` statements.
- [ ] **DDL Execution**: Configured columns (`phone_number VARCHAR(255)`, `age DOUBLE`) and indexes are created cleanly on SQLite, PostgreSQL, and MySQL.
- [ ] **Mass-Assignment Guard**: Submitting a field with `Input: false` returns HTTP 400 Bad Request.
- [ ] **Wire Format Parity**: `GET /get-session` returns custom fields as top-level JSON keys.
- [ ] **Data Persistence**: Round-trip `CreateUser` $\rightarrow$ `FindUserByID` $\rightarrow$ `UpdateUser` correctly persists and updates physical column values.
