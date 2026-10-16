package humaaccesstoken

import (
	"net/http"

	constant "github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/danielgtaylor/huma/v2"
)

const (
	RegisterUser        = constant.OperationId("Au-1-Register")
	VerifyUser          = constant.OperationId("Au-2-Verify")
	LoginUser           = constant.OperationId("Au-3-Login")
	RefreshTokenUser    = constant.OperationId("Au-4-RefreshToken")
	LogoutUser          = constant.OperationId("Au-5-Logout")
	ForgotPwdUser       = constant.OperationId("Au-6-ForgotPwd")
	ResetPwdUser        = constant.OperationId("Au-7-ResetPwd")
	GetMySessions       = constant.OperationId("Se-1-GetMySessions")
	DeleteMySessionById = constant.OperationId("Ad-2-DeleteMySessionById")
	GetMyProfile        = constant.OperationId("Pr_1-GetMyProfile")
	UpdateMyProfile     = constant.OperationId("Pr_2-UpdateMyProfile")
	ChangeMyPwd         = constant.OperationId("Pr_3-ChangeMyPassword")
	ChangeEmailReq      = constant.OperationId("Pr_4-ChangeEmailReq")
	ChangeEmailVerify   = constant.OperationId("Pr_5-ChangeEmailVerify")
)

var defaultEmptyRoles = []string{}

// SetupAccessTokenRoutes registers all legacy access-token / JWT endpoints on huma.API.
func SetupAccessTokenRoutes(api huma.API, handler *AccessTokenHandler, mdlware *middleware.AuthMiddleware, basePath string) {
	if basePath == "" {
		basePath = "/api/auth"
	}

	authTags := []string{"01-auth"}
	sessionTags := []string{"session"}
	profileTags := []string{"profile"}
	_ = profileTags

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
	var authMiddlewares huma.Middlewares
	if mdlware != nil {
		authMiddlewares = huma.Middlewares{
			mdlware.Authenticate(),
		}
	}

	// ─── Session Endpoints ───────────────────────────────────────────────────────
	sessPath := basePath + "/session"
	huma.Register(api, huma.Operation{
		OperationID: GetMySessions.Str(),
		Method:      http.MethodGet,
		Path:        sessPath,
		Summary:     "Get My Sessions (Access Token)",
		Tags:        sessionTags,
		Middlewares: authMiddlewares,
	}, handler.GetMySession)

	huma.Register(api, huma.Operation{
		OperationID: DeleteMySessionById.Str(),
		Method:      http.MethodPost,
		Path:        sessPath + "/{id}",
		Summary:     "Delete Session (Access Token)",
		Tags:        sessionTags,
		Middlewares: authMiddlewares,
	}, handler.DeleteMySession)

	
}

