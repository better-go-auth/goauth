package admin

import (
	"strings"

	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// SetupHumaRoutes mounts the Admin plugin routes onto a Huma API instance.
func (p *Plugin) SetupHumaRoutes(api huma.API, kit *pluginkit.Kit) {
	if p.service == nil {
		return
	}
	handler := humaadmin.NewAdminHandler(p.service, p.config, kit, p.authenticate)
	handler.Cfg = p.rootConfig
	handler.Cfg.Session.GoAuth = p.sessionConf
	// WithBasePath mounts the admin routes under another base path than the core routes
	if p.basePath != "" {
		handler.Cfg.BasePath = p.basePath
		if kit != nil {
			kit.BasePath = strings.TrimSuffix(p.basePath, "/")
		}
	}
	handler.AdminRepo = p.adminRepos.AdminRepo
	p.handler = handler
	humaadmin.SetupAdminRoutes(api, handler)
}
