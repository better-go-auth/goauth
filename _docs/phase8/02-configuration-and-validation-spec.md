# 02: Configuration & Validation Specification

## 1. Better-Auth Compatible Configuration API

To match Better Auth's developer experience, developers configure custom columns when initializing `goauth`:

```go
authServer := goauth.New(goauth.Config{
    Database: db,
    User: goauth.UserConfig{
        AdditionalFields: map[string]goauth.FieldConfig{
            "phoneNumber": {
                Type:        goauth.FieldTypeString,
                Required:    false,
                Input:       true,  // Can be supplied during signUp and updateUser
                Returned:    true,  // Included in /get-session and user responses
                Unique:      true,  // Generates UNIQUE KEY in database
                Index:       true,
                Validator:   validatePhoneNumber,
            },
            "loyaltyTier": {
                Type:        goauth.FieldTypeString,
                Default:     "standard",
                Input:       false, // Client cannot set this! Server/admin only
                Returned:    true,
            },
            "age": {
                Type:        goauth.FieldTypeNumber,
                Required:    false,
                Input:       true,
                Returned:    false, // Private to server; not returned to frontend
            },
        },
    },
    Session: goauth.SessionConfig{
        AdditionalFields: map[string]goauth.FieldConfig{
            "countryCode": {
                Type:     goauth.FieldTypeString,
                Returned: true,
            },
        },
    },
})
```

---

## 2. Configuration Struct Definitions

```go
package goauth

import "fmt"

type FieldType string

const (
    FieldTypeString  FieldType = "string"
    FieldTypeNumber  FieldType = "number"
    FieldTypeBoolean FieldType = "boolean"
    FieldTypeDate    FieldType = "date"
    FieldTypeJSON    FieldType = "json"
)

type FieldConfig struct {
    // Type defines the data type ("string", "number", "boolean", "date", "json").
    Type FieldType `json:"type"`

    // Required enforces non-null/non-empty values on insert.
    Required bool `json:"required,omitempty"`

    // Default sets a fallback value if omitted on insert.
    Default any `json:"defaultValue,omitempty"`

    // Input indicates if clients may provide this value in POST /sign-up/email or /update-user.
    // Default: true. Set to false for system/admin managed fields to prevent mass-assignment.
    Input *bool `json:"input,omitempty"`

    // Returned indicates if this field is serialized in public JSON responses.
    // Default: true. Set to false for sensitive data (e.g. internal score, age, SSN).
    Returned *bool `json:"returned,omitempty"`

    // Unique specifies if the database column should enforce unique values.
    Unique bool `json:"unique,omitempty"`

    // Index specifies if an index should be created on this column.
    Index bool `json:"index,omitempty"`

    // ColumnName overrides the database column name. Defaults to snake_case of key.
    ColumnName string `json:"columnName,omitempty"`

    // Validator is an optional function for custom domain validation.
    Validator func(val any) error `json:"-"`
}

func (f *FieldConfig) CanInput() bool {
    if f.Input == nil {
        return true // Default: allowed
    }
    return *f.Input
}

func (f *FieldConfig) IsReturned() bool {
    if f.Returned == nil {
        return true // Default: returned
    }
    return *f.Returned
}
```

---

## 3. Security: Mass-Assignment & Privilege Escalation Protection

A critical security vulnerability in authentication libraries is **Mass-Assignment** (over-posting). If an attacker sends `{ "email": "attacker@evil.com", "role": "admin", "loyaltyTier": "vip" }`, the server must strictly enforce field authorization.

```
Incoming Request Payload
{ "email": "...", "name": "...", "phoneNumber": "+123", "loyaltyTier": "vip" }
                             │
                             ▼
               Whitelisted against AdditionalFields
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
    "phoneNumber" (Input: true)     "loyaltyTier" (Input: false)
          ACCEPTED                   REJECTED / STRIPPED
             │                               │
             ▼                               ▼
      Passed to Database           Ignored (or HTTP 400 Error)
```

### 3.1. Sanitization Function
```go
package validation

import (
    "fmt"
    "time"
    "github.com/better-go-auth/goauth/src/common/autherr"
)

func SanitizeCustomInput(
    raw map[string]interface{},
    schema map[string]FieldConfig,
    isUpdate bool,
) (map[string]interface{}, error) {
    clean := make(map[string]interface{})

    for key, cfg := range schema {
        val, exists := raw[key]

        // 1. Check if client is trying to modify a protected field
        if exists && !cfg.CanInput() {
            return nil, fmt.Errorf("%w: field '%s' cannot be modified by client", autherr.ErrInvalidInput, key)
        }

        // 2. Handle missing fields on insert
        if !exists || val == nil {
            if cfg.Required && !isUpdate {
                if cfg.Default != nil {
                    clean[key] = cfg.Default
                } else {
                    return nil, fmt.Errorf("%w: required field '%s' is missing", autherr.ErrInvalidInput, key)
                }
            } else if cfg.Default != nil && !isUpdate {
                clean[key] = cfg.Default
            }
            continue
        }

        // 3. Type Coercion & Verification
        typedVal, err := coerceAndValidateType(key, val, cfg.Type)
        if err != nil {
            return nil, err
        }

        // 4. Custom Validator
        if cfg.Validator != nil {
            if err := cfg.Validator(typedVal); err != nil {
                return nil, fmt.Errorf("%w: invalid field '%s': %v", autherr.ErrInvalidInput, key, err)
            }
        }

        clean[key] = typedVal
    }

    return clean, nil
}
```

---

## 4. Type Coercion Engine

Because JSON represents all numbers as `float64` and dates as ISO-8601 strings, the validator coerces and validates Go types:

```go
func coerceAndValidateType(name string, val any, expected FieldType) (any, error) {
    switch expected {
    case FieldTypeString:
        s, ok := val.(string)
        if !ok {
            return nil, fmt.Errorf("field '%s' must be a string", name)
        }
        return s, nil

    case FieldTypeNumber:
        switch n := val.(type) {
        case float64:
            return n, nil
        case int:
            return float64(n), nil
        case int64:
            return float64(n), nil
        default:
            return nil, fmt.Errorf("field '%s' must be a numeric value", name)
        }

    case FieldTypeBoolean:
        b, ok := val.(bool)
        if !ok {
            return nil, fmt.Errorf("field '%s' must be a boolean", name)
        }
        return b, nil

    case FieldTypeDate:
        switch d := val.(type) {
        case time.Time:
            return d, nil
        case string:
            t, err := time.Parse(time.RFC3339, d)
            if err != nil {
                return nil, fmt.Errorf("field '%s' must be a valid RFC3339 timestamp", name)
            }
            return t, nil
        default:
            return nil, fmt.Errorf("field '%s' must be a date string or timestamp", name)
        }

    case FieldTypeJSON:
        return val, nil

    default:
        return val, nil
    }
}
```

---

## 5. Huma OpenAPI Integration

`goauth` uses [Huma](https://huma.rocks) for REST APIs and OpenAPI 3.1 schema generation.

To ensure clients see declared custom fields in OpenAPI specs:
1. `SignUpEmailInput` and `UpdateUserBody` already embed `_ struct{} json:"-" additionalProperties:"true"`.
2. When `goauth.New(...)` registers routes with Huma, a schema transformer dynamically appends configured `AdditionalFields` to the OpenAPI JSON Schema:

```go
func EnhanceOpenAPISchema(schema *huma.Schema, additionalFields map[string]FieldConfig) {
    if schema.Properties == nil {
        schema.Properties = make(map[string]*huma.Schema)
    }
    for name, cfg := range additionalFields {
        if !cfg.CanInput() {
            continue // Omit non-input fields from request schema
        }
        prop := &huma.Schema{}
        switch cfg.Type {
        case FieldTypeString:
            prop.Type = "string"
        case FieldTypeNumber:
            prop.Type = "number"
        case FieldTypeBoolean:
            prop.Type = "boolean"
        case FieldTypeDate:
            prop.Type = "string"
            prop.Format = "date-time"
        case FieldTypeJSON:
            prop.Type = "object"
        }
        schema.Properties[name] = prop
        if cfg.Required {
            schema.Required = append(schema.Required, name)
        }
    }
}
```
This enables frontend SDKs and Swagger/Redoc documentation to automatically generate typed forms for all custom fields!
