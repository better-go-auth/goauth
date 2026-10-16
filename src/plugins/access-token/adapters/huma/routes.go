package humaaccesstoken

import (
	"net/http"

	constant "github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/danielgtaylor/huma/v2"
)

const (
	RegisterUser        = constant.OperationId("Au-1-Register")
	LoginUser           = constant.OperationId("Au-3-Login")
	RefreshTokenUser    = constant.OperationId("Au-4-RefreshToken")
	// GetMySessions       = constant.OperationId("Se-1-GetMySessions")
	// DeleteMySessionById = constant.OperationId("Ad-2-DeleteMySessionById")
)

// SetupAccessTokenRoutes registers all legacy access-token / JWT endpoints on huma.API.
func SetupAccessTokenRoutes(api huma.API, handler *AccessTokenHandler, mdlware *middleware.AuthMiddleware, basePath string) {
	if basePath == "" {
		basePath = "/api/auth"
	}

	authTags := []string{"01-auth"}
	// sessionTags := []string{"session"}


	// ─── Auth Endpoints ──────────────────────────────────────────────────────────
	huma.Register(api, huma.Operation{
		OperationID: RegisterUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/signup",
		Summary:     "Register (Access Token)",
		Tags:        authTags,
	}, handler.Register)

	huma.Register(api, huma.Operation{
		OperationID: LoginUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/login",
		Summary:     "Login (Access Token)",
		Tags:        authTags,
	}, handler.Login)

	huma.Register(api, huma.Operation{
		OperationID: RefreshTokenUser.Str(),
		Method:      http.MethodPost,
		Path:        basePath + "/refresh",
		Summary:     "Refresh Token (Access Token)",
		Tags:        authTags,
	}, handler.RefreshToken)

	// Middlewares for protected routes
	// var authMiddlewares huma.Middlewares
	// if mdlware != nil {
	// 	authMiddlewares = huma.Middlewares{
	// 		mdlware.Authenticate(),
	// 	}
	// }
	_ = mdlware

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
