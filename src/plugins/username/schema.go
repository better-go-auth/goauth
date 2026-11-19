package username

import (
	"github.com/better-go-auth/goauth/src/common/dbhooks"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/schema"
)

// Schema implements plugins.SchemaProvider: better-auth's username schema (user username, unique and sortable,
// and displayUsername), with the configured normalizers as input transforms like better-auth's
// transform.input. Apps without the plugin get none of these columns.
func (p *Plugin) Schema() schema.PluginSchema {
	ps := schema.PluginFields(schema.PluginUsername)
	user := ps[schema.ModelUser]
	// Step 1: username: the configured normalizer (lower-case by default) for string input
	f := user.Fields["username"]
	f.TransformIn = func(v any) any {
		if s, ok := v.(string); ok {
			return p.config.Normalize(s)
		}
		return v
	}
	user.Fields["username"] = f
	// Step 2: displayUsername: the display normalizer (identity by default)
	d := user.Fields["displayUsername"]
	d.TransformIn = func(v any) any {
		if s, ok := v.(string); ok {
			return p.config.NormalizeDisplay(s)
		}
		return v
	}
	user.Fields["displayUsername"] = d
	ps[schema.ModelUser] = user
	return ps
}

// DatabaseHooks implements plugins.DatabaseHooksProvider: better-auth's user update hook of the username
// plugin, so usernames written by any endpoint (e.g. /admin/update-user) are validated and normalized.
func (p *Plugin) DatabaseHooks() dbhooks.Hooks {
	return dbhooks.Hooks{User: dbhooks.ModelHooks[models.User]{Update: dbhooks.UpdateHooks[models.User]{
		Before: p.service.BeforeUserUpdate,
	}}}
}
