package anonymous

import "github.com/better-go-auth/goauth/src/schema"

// Schema implements plugins.SchemaProvider: better-auth's anonymous schema (user isAnonymous, input:false,
// default false). Apps without the plugin get no isAnonymous column.
func (p *Plugin) Schema() schema.PluginSchema { return schema.PluginFields(schema.PluginAnonymous) }
