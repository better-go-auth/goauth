package org

import (
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// SetupHumaRoutes mounts org routes onto a Huma API instance.
// Requires an AuthHandler for authentication and the plugin's Service() for org logic.
func (p *OrgPlugin) SetupHumaRoutes(api huma.API, kit *pluginkit.Kit) {
	if p.service == nil {
		return
	}
	h := humaorg.NewOrgHandler(p.Service(), kit, p.authenticator)
	h.Cfg = p.authConfig
	p.handler = h
	humaorg.SetupOrgRoutes(api, h)
}
