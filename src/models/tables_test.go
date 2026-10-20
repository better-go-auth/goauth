package models

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNewNamingStrategyMultiTenancy(t *testing.T) {
	// Tenant 1
	ns1 := NewNamingStrategy("tenant1_", map[string]string{
		ModelUser: "members",
	})
	if got := ns1.TableName(ModelUser); got != "tenant1_members" {
		t.Errorf("tenant 1 user table: got %q, want %q", got, "tenant1_members")
	}
	if got := ns1.TableName(ModelSession); got != "tenant1_session" {
		t.Errorf("tenant 1 session table: got %q, want %q", got, "tenant1_session")
	}

	// Tenant 2
	ns2 := NewNamingStrategy("tenant2_", map[string]string{
		ModelUser: "accounts",
	})
	if got := ns2.TableName(ModelUser); got != "tenant2_accounts" {
		t.Errorf("tenant 2 user table: got %q, want %q", got, "tenant2_accounts")
	}
	if got := ns2.TableName(ModelSession); got != "tenant2_session" {
		t.Errorf("tenant 2 session table: got %q, want %q", got, "tenant2_session")
	}

	// Verify Tenant 1 was not affected by Tenant 2
	if got := ns1.TableName(ModelUser); got != "tenant1_members" {
		t.Errorf("tenant 1 user table after tenant 2: got %q, want %q", got, "tenant1_members")
	}

	// Test with GORM DB instances
	db1, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		NamingStrategy: ns1,
	})
	if err != nil {
		t.Fatalf("failed to open db1: %v", err)
	}

	db2, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		NamingStrategy: ns2,
	})
	if err != nil {
		t.Fatalf("failed to open db2: %v", err)
	}

	stmt1 := &gorm.Statement{DB: db1}
	if err := stmt1.Parse(&User{}); err != nil {
		t.Fatalf("parse db1 user: %v", err)
	}
	if stmt1.Schema.Table != "tenant1_members" {
		t.Errorf("db1 table name: got %q, want %q", stmt1.Schema.Table, "tenant1_members")
	}

	stmt2 := &gorm.Statement{DB: db2}
	if err := stmt2.Parse(&User{}); err != nil {
		t.Fatalf("parse db2 user: %v", err)
	}
	if stmt2.Schema.Table != "tenant2_accounts" {
		t.Errorf("db2 table name: got %q, want %q", stmt2.Schema.Table, "tenant2_accounts")
	}
}
