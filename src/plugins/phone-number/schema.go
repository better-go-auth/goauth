package phonenumber

import (
	"context"
	"reflect"

	"github.com/better-go-auth/goauth/src/common/dbhooks"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/schema"
)

// Schema implements plugins.SchemaProvider: better-auth's phone-number schema (user phoneNumber, unique and
// sortable, and phoneNumberVerified, input:false). Apps without the plugin get none of these columns.
func (p *Plugin) Schema() schema.PluginSchema { return schema.PluginFields(schema.PluginPhoneNumber) }

// DatabaseHooks implements plugins.DatabaseHooksProvider: better-auth's user update hook of the phone-number
// plugin: clearing phoneNumber (null) also clears phoneNumberVerified.
func (p *Plugin) DatabaseHooks() dbhooks.Hooks {
	return dbhooks.Hooks{User: dbhooks.ModelHooks[models.User]{Update: dbhooks.UpdateHooks[models.User]{
		Before: func(_ context.Context, data map[string]any) error {
			if v, ok := data["phoneNumber"]; ok && isNull(v) {
				data["phoneNumberVerified"] = false
			}
			return nil
		},
	}}}
}

// isNull reports whether v is nil or a nil pointer (JSON null).
func isNull(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}
