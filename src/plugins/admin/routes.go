package admin

import (
	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"github.com/danielgtaylor/huma/v2"
)

// SetupHumaRoutes mounts the Admin plugin routes onto a Huma API instance.
func (p *Plugin) SetupHumaRoutes(api huma.API, mdlware *middleware.AuthMiddleware) {
	if p.service == nil {
		return
	}
	handler := humaadmin.NewAdminHandler(p.service, p.config, mdlware, p.authenticate)
	handler.Cfg.SessionConfig = p.sessionConf
	if p.basePath != "" {
		handler.Cfg.BasePath = p.basePath
	}
	handler.AdminRepo = p.adminRepos.AdminRepo
	p.handler = handler
	humaadmin.SetupAdminRoutes(api, handler)
}
