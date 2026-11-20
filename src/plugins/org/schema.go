package org

import (
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/schema"
)

// Schema implements plugins.SchemaProvider. It returns two things:
//   - better-auth's organization tables: organization, member and invitation, team and teamMember with teams,
//     organizationRole with dynamic access control (goauth's migrator creates them);
//   - the organization plugin's session fields (better-auth's activeOrganizationId, and activeTeamId with
//     teams, plus goauth's activeOrganizationType / Role). Without teams activeTeamId keeps its column
//     (goauth always had it) but only appears in the session JSON when set, like better-auth, whose schema
//     has no activeTeamId then.
func (p *OrgPlugin) Schema() schema.PluginSchema {
	// Step 1: the session fields the plugin adds to the core session model
	ps := schema.PluginFields(schema.PluginOrg)
	if !p.teamsEnabled() {
		session := ps[schema.ModelSession]
		f := session.Fields["activeTeamId"]
		f.OmitEmpty = true
		session.Fields["activeTeamId"] = f
		ps[schema.ModelSession] = session
	}
	// Step 2: the organization tables
	for name, model := range orgmodels.Schema(p.teamsEnabled(), p.dynamicACEnabled()) {
		ps[name] = model
	}
	return ps
}
