package models

import (
	"testing"
)

// mockNamer implements TableNamer for testing.
type mockNamer struct {
	prefix string
}

func (m mockNamer) TableName(table string) string {
	return m.prefix + table
}

func TestTableNames_PureGo(t *testing.T) {
	// Step 1: Default global table names without prefix
	SetTableNames("", nil)
	if got := TableName(ModelUser); got != "user" {
		t.Errorf("default user table: got %q, want %q", got, "user")
	}
	if got := TableName(ModelSession); got != "session" {
		t.Errorf("default session table: got %q, want %q", got, "session")
	}

	// Step 2: Global prefix and overrides
	SetTableNames("auth_", map[string]string{
		ModelUser: "app_users",
	})
	if got := TableName(ModelUser); got != "auth_app_users" {
		t.Errorf("overridden user table: got %q, want %q", got, "auth_app_users")
	}
	if got := TableName(ModelSession); got != "auth_session" {
		t.Errorf("prefixed session table: got %q, want %q", got, "auth_session")
	}

	// Step 3: ResolveTableName with custom TableNamer
	custom := mockNamer{prefix: "custom_"}
	if got := ResolveTableName(custom, ModelUser); got != "custom_app_users" {
		t.Errorf("custom namer with override: got %q, want %q", got, "custom_app_users")
	}
	if got := ResolveTableName(custom, ModelVerification); got != "custom_verification" {
		t.Errorf("custom namer without override: got %q, want %q", got, "custom_verification")
	}

	// Step 4: ResolveTableName with nil namer falls back to global
	if got := ResolveTableName(nil, ModelUser); got != "auth_app_users" {
		t.Errorf("nil namer fallback: got %q, want %q", got, "auth_app_users")
	}

	// Reset for other tests
	SetTableNames("", nil)
}
