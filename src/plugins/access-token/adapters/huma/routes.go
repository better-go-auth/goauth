package humaaccesstoken

import (
	"net/http"

	constant "github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

const (
	RegisterUser     = constant.OperationId("Au-1-Register")
	LoginUser        = constant.OperationId("Au-3-Login")
	RefreshTokenUser = constant.OperationId("Au-4-RefreshToken")
	// GetMySessions       = constant.OperationId("Se-1-GetMySessions")
	// DeleteMySessionById = constant.OperationId("Ad-2-DeleteMySessionById")
)

// SetupAccessTokenRoutes registers all legacy access-token / JWT endpoints through pluginkit (base path,
// origin / CSRF check, disabled routes and rate limiting like every other plugin).
func SetupAccessTokenRoutes(api huma.API, handler *AccessTokenHandler, kit *pluginkit.Kit) {
	authTags := []string{"01-auth"}
	// sessionTags := []string{"session"}

	// ─── Auth Endpoints ──────────────────────────────────────────────────────────
	// sign-up and sign-in get the sign-in CSRF rules (pluginkit.Form), like the core sign-in routes
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: RegisterUser.Str(), Method: http.MethodPost, Path: "/signup",
		Summary: "Register (Access Token)", Tags: authTags, Access: pluginkit.Form,
	}, handler.Register)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: LoginUser.Str(), Method: http.MethodPost, Path: "/login",
		Summary: "Login (Access Token)", Tags: authTags, Access: pluginkit.Form,
	}, handler.Login)

	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: RefreshTokenUser.Str(), Method: http.MethodPost, Path: "/refresh",
		Summary: "Refresh Token (Access Token)", Tags: authTags, Access: pluginkit.Public,
	}, handler.RefreshToken)

	// ─── Session Endpoints ───────────────────────────────────────────────────────
	// Note: Session endpoints (/session, /session/{id}) are commented out as they
	// are superseded by standard Better Auth core endpoints:
	// - GET /api/auth/list-sessions
	// - GET /api/auth/get-session
	// - POST /api/auth/revoke-session
	// - POST /api/auth/sign-out
	//
	// sessPath := basePath + "/session"
	// huma.Register(api, huma.Operation{
	// 	OperationID: GetMySessions.Str(),
	// 	Method:      http.MethodGet,
	// 	Path:        sessPath,
	// 	Summary:     "Get My Sessions (Access Token)",
	// 	Tags:        sessionTags,
	// 	Middlewares: authMiddlewares,
	// }, handler.GetMySession)
	//
	// huma.Register(api, huma.Operation{
	// 	OperationID: DeleteMySessionById.Str(),
	// 	Method:      http.MethodPost,
	// 	Path:        sessPath + "/{id}",
	// 	Summary:     "Delete Session (Access Token)",
	// 	Tags:        sessionTags,
	// 	Middlewares: authMiddlewares,
	// }, handler.DeleteMySession)
}
