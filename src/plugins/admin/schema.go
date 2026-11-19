package admin

import "github.com/better-go-auth/goauth/src/schema"

// Schema implements plugins.SchemaProvider: better-auth's admin schema (user role, banned, banReason,
// banExpires; session impersonatedBy). Apps without the admin plugin get none of these columns, and the user /
// session JSON of apps with it always carries them (false / null when unset).
func (p *Plugin) Schema() schema.PluginSchema { return schema.PluginFields(schema.PluginAdmin) }
