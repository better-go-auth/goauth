package dtos

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/schema"
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

// withOutput installs an output schema for the test (installed plugins) and restores the default afterwards.
func withOutput(t *testing.T, opts schema.Options, installed []string) *schema.Registry {
	t.Helper()
	opts.InstalledPlugins = installed
	reg := schema.MustBuild(opts)
	SetOutputSchema(reg, installed)
	t.Cleanup(func() { SetOutputSchema(nil, nil) })
	return reg
}

func TestUserResponse_InstalledPluginFieldsAreAlwaysPresent(t *testing.T) {
	u := UserResponse{ID: "u1", Role: "user"}

	// Step 1: no plugin installed: plugin fields are not part of the user schema
	withOutput(t, schema.Options{}, []string{})
	got := decode(t, u)
	for _, k := range []string{"role", "banned", "twoFactorEnabled", "phoneNumber", "username", "isAnonymous"} {
		if _, ok := got[k]; ok {
			t.Fatalf("%s should be omitted without its plugin: %v", k, got)
		}
	}

	// Step 2: admin + two-factor + phone-number installed: their fields are always written (B10)
	withOutput(t, schema.Options{}, []string{"admin", "two-factor", "phone-number"})
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

func TestUserResponse_PluginFieldsOfAllPluginRegistry(t *testing.T) {
	// a registry with every plugin column (GORMRepositories) but only admin installed: other plugins'
	// fields appear only when set
	reg := schema.MustBuild(schema.Options{})
	SetOutputSchema(reg, []string{"admin"})
	t.Cleanup(func() { SetOutputSchema(nil, nil) })
	got := decode(t, UserResponse{ID: "u1"})
	if got["role"] != "user" || got["banned"] != false {
		t.Fatalf("admin fields missing: %v", got)
	}
	for _, k := range []string{"twoFactorEnabled", "phoneNumber", "isAnonymous", "username"} {
		if _, ok := got[k]; ok {
			t.Fatalf("%s belongs to a plugin that isn't installed: %v", k, got)
		}
	}
	name := "neo"
	got = decode(t, UserResponse{ID: "u1", Username: &name})
	if got["username"] != "neo" {
		t.Fatalf("set fields of other plugins are written: %v", got)
	}
}

func TestSessionData_InstalledPluginFieldsAreNull(t *testing.T) {
	withOutput(t, schema.Options{}, []string{"admin", "org"})
	got := decode(t, SessionData{ID: "s1"})
	for _, k := range []string{"activeOrganizationId", "impersonatedBy"} {
		if v, ok := got[k]; !ok || v != nil {
			t.Fatalf("%s should be null: %v", k, got)
		}
	}
	// goauth's own fields only appear when set
	for _, k := range []string{"activeOrganizationRole", "deviceId", "lastUsedAt"} {
		if _, ok := got[k]; ok {
			t.Fatalf("%s should be omitted: %v", k, got)
		}
	}
}

func TestOutput_AdditionalFields(t *testing.T) {
	f := schema.Bool(false)
	withOutput(t, schema.Options{Models: map[string]schema.ModelOptions{
		schema.ModelUser: {AdditionalFields: map[string]schema.Field{
			"plan":     {Type: schema.String, Default: "free"},
			"birthday": {Type: schema.Date},
			"secret":   {Type: schema.String, Returned: f},
			"tags":     {Type: schema.StringArray},
		}},
		schema.ModelSession: {AdditionalFields: map[string]schema.Field{"device": {Type: schema.String}}},
	}}, []string{})

	// Step 1: unset additional fields are null; returned:false is hidden even when set; unknown extras dropped
	birthday := time.Date(2000, 1, 2, 3, 4, 5, 6_000_000, time.UTC)
	u := UserResponse{ID: "u1", Name: "A", Extra: map[string]any{"plan": "pro", "secret": "x", "birthday": birthday, "junk": 1}}
	got := decode(t, u)
	if got["plan"] != "pro" || got["birthday"] != "2000-01-02T03:04:05.006Z" {
		t.Fatalf("extras: %v", got)
	}
	if v, ok := got["tags"]; !ok || v != nil {
		t.Fatalf("unset additional field must be null: %v", got)
	}
	if _, ok := got["secret"]; ok {
		t.Fatalf("returned:false must be hidden: %v", got)
	}
	if _, ok := got["junk"]; ok {
		t.Fatalf("unknown keys must be dropped: %v", got)
	}
	// goauth's own user columns stay out of the JSON unless set
	if _, ok := got["firstName"]; ok {
		t.Fatalf("firstName must be omitted: %v", got)
	}

	// Step 2: round trip (cookie cache / secondary storage): extras come back with their Go types
	b, _ := json.Marshal(u)
	var back UserResponse
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Extra["plan"] != "pro" || !back.Extra["birthday"].(time.Time).Equal(birthday.Truncate(time.Millisecond)) {
		t.Fatalf("round trip: %#v", back.Extra)
	}
	if _, ok := back.Extra["tags"]; ok {
		t.Fatalf("null values are not kept: %#v", back.Extra)
	}

	// Step 3: session extras
	s := SessionData{ID: "s1", Extra: map[string]any{"device": "phone"}}
	sb, _ := json.Marshal(s)
	if !strings.Contains(string(sb), `"device":"phone"`) {
		t.Fatalf("session extra: %s", sb)
	}
	var sback SessionData
	if err := json.Unmarshal(sb, &sback); err != nil || sback.Extra["device"] != "phone" {
		t.Fatalf("session round trip: %#v %v", sback.Extra, err)
	}
}
