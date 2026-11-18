package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// Permission defines dynamic access control permissions mapping resource keys to allowed actions.
// E.g. {"project": ["create", "read"], "billing": ["read"]}.
// Serialized to JSON text in database tables.
type Permission map[string][]string

// Value implements the database/sql/driver.Valuer interface for database storage.
func (p Permission) Value() (driver.Value, error) {
	// Step 1: If map is nil, serialize as empty JSON object to avoid DB null violations
	if p == nil {
		return "{}", nil
	}
	// Step 2: Marshal map to JSON bytes
	bytes, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Permission to JSON: %w", err)
	}
	// Step 3: Return JSON string representation
	return string(bytes), nil
}

// Scan implements the database/sql.Scanner interface for database retrieval.
func (p *Permission) Scan(value any) error {
	// Step 1: Handle nil database value
	if value == nil {
		*p = make(Permission)
		return nil
	}

	// Step 2: Extract bytes depending on driver return type ([]byte or string)
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("unsupported type for Permission scan: %T", value)
	}

	// Step 3: Check for empty value or SQL NULL representation
	if len(bytes) == 0 || string(bytes) == "null" {
		*p = make(Permission)
		return nil
	}

	// Step 4: Unmarshal JSON into map
	var m map[string][]string
	if err := json.Unmarshal(bytes, &m); err != nil {
		return fmt.Errorf("failed to unmarshal Permission JSON: %w", err)
	}

	*p = m
	return nil
}

// UnmarshalJSON implements json.Unmarshaler to accept both direct JSON objects and stringified JSON.
func (p *Permission) UnmarshalJSON(data []byte) error {
	// Step 1: Try unmarshaling as a direct JSON object (map[string][]string)
	var direct map[string][]string
	if err := json.Unmarshal(data, &direct); err == nil {
		*p = direct
		return nil
	}

	// Step 2: Try unmarshaling as a stringified JSON document (e.g. "\"{\\\"project\\\": [\\\"read\\\"]}\"")
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		var decoded map[string][]string
		if err := json.Unmarshal([]byte(str), &decoded); err != nil {
			return fmt.Errorf("failed to decode inner permission string: %w", err)
		}
		*p = decoded
		return nil
	}

	return fmt.Errorf("invalid JSON format for Permission: %s", string(data))
}

// HasAction checks whether the permission grant permits the given action on the specified resource.
// Supports wildcard resource "*" and wildcard action "*".
func (p Permission) HasAction(resource, action string) bool {
	if p == nil {
		return false
	}
	// Step 1: Check wildcard resource "*"
	if wildcardActions, ok := p["*"]; ok {
		for _, a := range wildcardActions {
			if a == "*" || a == action {
				return true
			}
		}
	}
	// Step 2: Check target resource
	if actions, ok := p[resource]; ok {
		for _, a := range actions {
			if a == "*" || a == action {
				return true
			}
		}
	}
	return false
}

// ParsePermission parses an input (Permission, map[string][]string, JSON string, or bytes) into a Permission.
func ParsePermission(v any) (Permission, error) {
	// Step 1: Check if already Permission
	if p, ok := v.(Permission); ok {
		return p, nil
	}
	// Step 2: Check if standard map[string][]string
	if m, ok := v.(map[string][]string); ok {
		return Permission(m), nil
	}
	// Step 3: Check if string
	if s, ok := v.(string); ok {
		var p Permission
		if err := json.Unmarshal([]byte(s), &p); err != nil {
			return nil, fmt.Errorf("invalid permission JSON: %w", err)
		}
		return p, nil
	}
	// Step 4: Check if byte slice
	if b, ok := v.([]byte); ok {
		var p Permission
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("invalid permission JSON: %w", err)
		}
		return p, nil
	}
	// Step 5: Fallback to JSON marshal and unmarshal roundtrip
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to parse permission: %w", err)
	}
	var p Permission
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("failed to parse permission: %w", err)
	}
	return p, nil
}

type Operations []string

// Value implements the database/sql/driver.Valuer interface for database storage.
func (o Operations) Value() (driver.Value, error) {
	// Step 1: If slice is nil or empty, serialize as empty JSON array to avoid DB null violations
	if o == nil {
		return "[]", nil
	}
	// Step 2: Marshal slice to JSON bytes
	bytes, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Operations to JSON: %w", err)
	}
	// Step 3: Return JSON string representation
	return string(bytes), nil
}

// Scan implements the database/sql.Scanner interface for database retrieval.
func (o *Operations) Scan(value any) error {
	// Step 1: Handle nil database value
	if value == nil {
		*o = make(Operations, 0)
		return nil
	}

	// Step 2: Extract bytes depending on driver return type ([]byte or string)
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("unsupported type for Operations scan: %T", value)
	}

	// Step 3: Check for empty value or SQL NULL representation
	if len(bytes) == 0 || string(bytes) == "null" {
		*o = make(Operations, 0)
		return nil
	}

	// Step 4: Unmarshal JSON into string slice
	var s []string
	if err := json.Unmarshal(bytes, &s); err != nil {
		return fmt.Errorf("failed to unmarshal Operations JSON: %w", err)
	}

	*o = s
	return nil
}

// UnmarshalJSON implements json.Unmarshaler to accept both direct JSON arrays and stringified JSON arrays.
func (o *Operations) UnmarshalJSON(data []byte) error {
	// Step 1: Try unmarshaling as a direct JSON array ([]string)
	var direct []string
	if err := json.Unmarshal(data, &direct); err == nil {
		*o = direct
		return nil
	}

	// Step 2: Try unmarshaling as a stringified JSON document (e.g. "\"[\\\"op1\\\", \\\"op2\\\"]\"")
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		var decoded []string
		if err := json.Unmarshal([]byte(str), &decoded); err != nil {
			return fmt.Errorf("failed to decode inner operations string: %w", err)
		}
		*o = decoded
		return nil
	}

	return fmt.Errorf("invalid JSON format for Operations: %s", string(data))
}

// HasOp checks whether the Operations slice permits the given operation ID.
// Supports exact match and wildcard "*".
func (o Operations) HasOp(operationID string) bool {
	// Step 1: Guard against nil or empty operations
	if len(o) == 0 {
		return false
	}
	// Step 2: Check each allowed operation for wildcard or exact match
	for _, op := range o {
		if op == "*" || op == operationID {
			return true
		}
	}
	return false
}

// ParseOperations parses an input (Operations, []string, JSON string, or bytes) into an Operations slice.
func ParseOperations(v any) (Operations, error) {
	// Step 1: Check if already Operations
	if ops, ok := v.(Operations); ok {
		return ops, nil
	}
	// Step 2: Check if standard []string
	if s, ok := v.([]string); ok {
		return Operations(s), nil
	}
	// Step 3: Check if string
	if s, ok := v.(string); ok {
		var ops Operations
		if err := json.Unmarshal([]byte(s), &ops); err != nil {
			return nil, fmt.Errorf("invalid operations JSON: %w", err)
		}
		return ops, nil
	}
	// Step 4: Check if byte slice
	if b, ok := v.([]byte); ok {
		var ops Operations
		if err := json.Unmarshal(b, &ops); err != nil {
			return nil, fmt.Errorf("invalid operations JSON: %w", err)
		}
		return ops, nil
	}
	// Step 5: Check if generic []any slice (common in unmarshaled JSON payloads)
	if slice, ok := v.([]any); ok {
		ops := make(Operations, 0, len(slice))
		for _, item := range slice {
			if str, ok := item.(string); ok {
				ops = append(ops, str)
			}
		}
		return ops, nil
	}
	// Step 6: Fallback to JSON marshal and unmarshal roundtrip
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to parse operations: %w", err)
	}
	var ops Operations
	if err := json.Unmarshal(b, &ops); err != nil {
		return nil, fmt.Errorf("failed to parse operations: %w", err)
	}
	return ops, nil
}
