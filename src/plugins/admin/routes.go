package admin

import (
	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	"github.com/danielgtaylor/huma/v2"
)

// SetupHumaRoutes mounts the Admin plugin routes onto a Huma API instance.
func (p *Plugin) SetupHumaRoutes(api huma.API) {
	if p.service == nil {
		return
	}
	handler := humaadmin.NewAdminHandler(p.service, p.config)
	// if p.jwtSecret != "" {
	// 	handler.JwtSecret = p.jwtSecret
	// }
	if p.basePath != "" {
		handler.Cfg.BasePath = p.basePath
	}
	handler.AdminRepo = p.adminRepos.AdminRepo
	humaadmin.SetupAdminRoutes(api, handler)
}
