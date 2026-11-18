package gormutil

import (
	"testing"

	"github.com/better-go-auth/goauth/src/models"
	goauthschema "github.com/better-go-auth/goauth/src/schema"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNewNamingStrategyMultiTenancy(t *testing.T) {
	// Tenant 1
	ns1 := NewNamingStrategy("tenant1_", map[string]string{
		models.ModelUser: "members",
	})
	if got := ns1.TableName(models.ModelUser); got != "tenant1_members" {
		t.Errorf("tenant 1 user table: got %q, want %q", got, "tenant1_members")
	}
	if got := ns1.TableName(models.ModelSession); got != "tenant1_session" {
		t.Errorf("tenant 1 session table: got %q, want %q", got, "tenant1_session")
	}

	// Tenant 2
	ns2 := NewNamingStrategy("tenant2_", map[string]string{
		models.ModelUser: "accounts",
	})
	if got := ns2.TableName(models.ModelUser); got != "tenant2_accounts" {
		t.Errorf("tenant 2 user table: got %q, want %q", got, "tenant2_accounts")
	}
	if got := ns2.TableName(models.ModelSession); got != "tenant2_session" {
		t.Errorf("tenant 2 session table: got %q, want %q", got, "tenant2_session")
	}

	// Verify Tenant 1 was not affected by Tenant 2
	if got := ns1.TableName(models.ModelUser); got != "tenant1_members" {
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
	if err := stmt1.Parse(&models.User{}); err != nil {
		t.Fatalf("parse db1 user: %v", err)
	}
	if stmt1.Schema.Table != "tenant1_members" {
		t.Errorf("db1 table name: got %q, want %q", stmt1.Schema.Table, "tenant1_members")
	}

	stmt2 := &gorm.Statement{DB: db2}
	if err := stmt2.Parse(&models.User{}); err != nil {
		t.Fatalf("parse db2 user: %v", err)
	}
	if stmt2.Schema.Table != "tenant2_accounts" {
		t.Errorf("db2 table name: got %q, want %q", stmt2.Schema.Table, "tenant2_accounts")
	}
}

// TestNamingStrategyWithRegistry: GORM column names follow the registry (camel case, Fields renames) for
// registry tables and camelCase for GORM-only tables, with better-auth's irregular names.
func TestNamingStrategyWithRegistry(t *testing.T) {
	camel := goauthschema.MustBuild(goauthschema.Options{ColumnCase: goauthschema.Camel, Models: map[string]goauthschema.ModelOptions{
		"user": {ModelName: "users", Fields: map[string]string{"name": "full_name"}},
	}})
	ns := NewNamingStrategy("", map[string]string{"user": "users"}, WithRegistry(camel))
	cases := map[[2]string]string{
		{"users", "EmailVerified"}:   "emailVerified",
		{"users", "Name"}:            "full_name",
		{"users", "LastLoginIP"}:     "lastLoginIP",
		{"session", "UserID"}:        "userId",
		{"session", "IPAddress"}:     "ipAddress",
		{"twoFactor", "BackupCodes"}: "backupCodes",
		{"passkey", "CredentialID"}:  "credentialID",
		{"member", "OrganizationID"}: "organizationId",
	}
	for in, want := range cases {
		if got := ns.ColumnName(in[0], in[1]); got != want {
			t.Errorf("ColumnName(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
	// snake: registry renames only, GORM's names elsewhere
	snake := goauthschema.MustBuild(goauthschema.Options{Models: map[string]goauthschema.ModelOptions{"session": {Fields: map[string]string{"token": "session_token"}}}})
	ns = NewNamingStrategy("", nil, WithRegistry(snake))
	if got := ns.ColumnName("session", "Token"); got != "session_token" {
		t.Errorf("renamed token = %q", got)
	}
	if got := ns.ColumnName("passkey", "CredentialID"); got != "credential_id" {
		t.Errorf("snake passkey column = %q", got)
	}
	if got := CamelFromSnake("access_token_expires_at"); got != "accessTokenExpiresAt" {
		t.Errorf("CamelFromSnake = %q", got)
	}
}
