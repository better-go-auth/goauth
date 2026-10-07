package auth

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// protectedSessionFields are never client-writable: identity, lifetime, request metadata and plugin-managed state
// (the org plugin's set-active checks membership before writing activeOrganizationId).
var protectedSessionFields = map[string]bool{
	"id": true, "userId": true, "token": true, "expiresAt": true, "createdAt": true, "updatedAt": true,
	"ipAddress": true, "userAgent": true, "impersonatedBy": true,
	"activeOrganizationId": true, "activeTeamId": true, "lastUsedAt": true,
}

// sessionStringFields maps the JSON name of every string field of models.Session to its Go field name.
func sessionStringFields() map[string]string {
	out := map[string]string{}
	t := reflect.TypeOf(models.Session{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if ft.Kind() != reflect.String || name == "" || name == "-" {
			continue
		}
		out[name] = f.Name
	}
	return out
}

// updatableSessionFields resolves GoAuth.Session.UpdatableFields to Go field names.
// A field must be a non-protected string field of models.Session that the cached session shape also carries.
func updatableSessionFields(cfg config.AuthConfig) (map[string]string, error) {
	known := sessionStringFields()
	cached := reflect.TypeOf(dtos.BetterAuthSession{})
	out := map[string]string{}
	for _, name := range cfg.GoAuth.Session.UpdatableFields {
		if protectedSessionFields[name] {
			return nil, fmt.Errorf("goauth: session field %q cannot be client-updatable", name)
		}
		goName, ok := known[name]
		if !ok {
			return nil, fmt.Errorf("goauth: GoAuth.Session.UpdatableFields: %q is not a string field of the session model", name)
		}
		if _, ok := cached.FieldByName(goName); !ok {
			return nil, fmt.Errorf("goauth: GoAuth.Session.UpdatableFields: %q is missing from dtos.BetterAuthSession", name)
		}
		out[name] = goName
	}
	return out, nil
}

// ValidateConfig reports configuration errors the service would otherwise only hit at request time.
func ValidateConfig(cfg config.AuthConfig) error {
	_, err := updatableSessionFields(cfg)
	return err
}
