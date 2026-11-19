package org

import "github.com/better-go-auth/goauth/src/schema"

// Schema implements plugins.SchemaProvider: the organization plugin's session fields (better-auth's
// activeOrganizationId, and activeTeamId with teams, plus goauth's activeOrganizationType / Role). Without
// teams activeTeamId keeps its column (goauth always had it) but only appears in the session JSON when set,
// like better-auth, whose schema has no activeTeamId then.
//
// NOTE for the organization tables: when they move to the schema registry, merge their models into the
// returned PluginSchema.
func (p *OrgPlugin) Schema() schema.PluginSchema {
	ps := schema.PluginFields(schema.PluginOrg)
	if p.Config.Teams == nil || !p.Config.Teams.Enabled {
		session := ps[schema.ModelSession]
		f := session.Fields["activeTeamId"]
		f.OmitEmpty = true
		session.Fields["activeTeamId"] = f
		ps[schema.ModelSession] = session
	}
	return ps
}
