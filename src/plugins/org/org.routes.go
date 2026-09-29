package org

import (
	"github.com/better-go-auth/goauth/src/common/middleware"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	"github.com/danielgtaylor/huma/v2"
)

// SetupHumaRoutes mounts org routes onto a Huma API instance.
// Requires an AuthHandler for authentication and the plugin's Service() for org logic.
func (p *OrgPlugin) SetupHumaRoutes(api huma.API, mdlware *middleware.AuthMiddleware) {
	if p.service == nil {
		return
	}
	h := humaorg.NewOrgHandler(p.Service(), mdlware, p.authenticator)
	h.Cfg = p.authConfig
	p.handler = h
	humaorg.SetupOrgRoutes(api, h)
}
