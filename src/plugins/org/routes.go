package org

import (
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	"github.com/danielgtaylor/huma/v2"
)

// SetupHumaRoutes mounts org routes onto a Huma API instance.
// Requires an AuthHandler for authentication and the plugin's Service() for org logic.
func (p *Plugin) SetupHumaRoutes(api huma.API) {
	if p.service == nil {
		return
	}
	h := humaorg.NewOrgHandler(p.Service())
	humaorg.SetupOrgRoutes(api, h)
}
