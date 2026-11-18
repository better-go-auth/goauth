package dtos

import (
	"encoding/json"
	"testing"
)

// decode marshals v and decodes it into a map so field presence can be checked.
func decode(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("invalid JSON %s: %v", b, err)
	}
	return out
}

func TestUserResponse_InstalledPluginFieldsAreAlwaysPresent(t *testing.T) {
	defer SetInstalledSchemaFields()
	u := UserResponse{ID: "u1", Role: "user"}

	// Step 1: no plugin installed: zero plugin fields are omitted, the default "user" role too
	SetInstalledSchemaFields()
	got := decode(t, u)
	for _, k := range []string{"role", "banned", "twoFactorEnabled", "phoneNumber", "username", "isAnonymous"} {
		if _, ok := got[k]; ok {
			t.Fatalf("%s should be omitted without its plugin: %v", k, got)
		}
	}

	// Step 2: admin + two-factor + phone-number installed: their fields are always written
	SetInstalledSchemaFields(
		SchemaFields{User: []string{FieldRole, FieldBanned, FieldBanReason, FieldBanExpires}},
		SchemaFields{User: []string{FieldTwoFactorEnabled}},
		SchemaFields{User: []string{FieldPhoneNumber, FieldPhoneNumberVerified}},
	)
	got = decode(t, u)
	if got["role"] != "user" || got["banned"] != false || got["twoFactorEnabled"] != false {
		t.Fatalf("installed plugin fields missing: %v", got)
	}
	for _, k := range []string{"banReason", "banExpires", "phoneNumber", "phoneNumberVerified"} {
		if v, ok := got[k]; !ok || v != nil {
			t.Fatalf("%s should be null: %v", k, got)
		}
	}
	if _, ok := got["username"]; ok {
		t.Fatalf("username plugin is not installed: %v", got)
	}
}

func TestSessionData_InstalledPluginFieldsAreNull(t *testing.T) {
	defer SetInstalledSchemaFields()
	SetInstalledSchemaFields(SchemaFields{Session: []string{FieldActiveOrganizationID, FieldImpersonatedBy}})
	got := decode(t, SessionData{ID: "s1"})
	for _, k := range []string{"activeOrganizationId", "impersonatedBy"} {
		if v, ok := got[k]; !ok || v != nil {
			t.Fatalf("%s should be null: %v", k, got)
		}
	}
	if _, ok := got["activeTeamId"]; ok {
		t.Fatalf("activeTeamId needs teams: %v", got)
	}
}
