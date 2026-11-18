package humaaccesstoken

import (
	"context"
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	services "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
)

// Names of the legacy JWT cookies set by /login and /refresh (moved here from the core common package).
const (
	AccessTokenCookie  = "access-token"
	RefreshTokenCookie = "refresh-token"
)

// AccessTokenHandler provides Huma handlers for access-token / JWT flows.
type AccessTokenHandler struct {
	AuthServ    services.IAccessTokenAuthService
	SessionServ services.IAccessTokenSessionService

	// SessionRepo repo_interfaces.ISessionRepo
	Config  *accesstokenconfig.SessionGoAuth
	Cookies CookieAttrs
}

func NewAccessTokenHandler(authserv services.IAccessTokenAuthService, sessionserv services.IAccessTokenSessionService, config *accesstokenconfig.SessionGoAuth, cookies CookieAttrs) *AccessTokenHandler {
	return &AccessTokenHandler{
		AuthServ:    authserv,
		SessionServ: sessionserv,
		Config:      config,
		Cookies:     cookies,
	}
}

func (h *AccessTokenHandler) tokenCookies(tokens *accesstokendtos.AuthTokens) []http.Cookie {
	if tokens == nil {
		return nil
	}
	accessExpiry := h.Config.JWT.AccessExpiresIn
	refreshExpiry := h.Cookies.RefreshMaxAge
	if refreshExpiry <= 0 {
		refreshExpiry = 7 * 24 * time.Hour
	}
	return []http.Cookie{
		CreateCookie(AccessTokenCookie, tokens.AccessToken, accessExpiry, h.Cookies),
		CreateCookie(RefreshTokenCookie, tokens.RefreshToken, refreshExpiry, h.Cookies),
	}
}

// Register handles POST /signup.
func (h *AccessTokenHandler) Register(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.RegisterClientInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.SignUpResponse]], error) {
	usr, err := h.AuthServ.RegisterWithEmail(ctx, inputs.Body)
	if err != nil {
		return nil, legacyError(ctx, http.StatusBadRequest, err)
	}

	resp := authDtos.SignUpResponse{
		User:  &usr.User,
		Token: nil,
	}
	gresp := dtos.SuccessCreated(resp, 1)
	return humatypes.MakeResPtr(&gresp, 200), nil
}

// Login handles POST /login.
func (h *AccessTokenHandler) Login(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.LoginData]) (*humatypes.HumaRes[dtos.GResp[accesstokendtos.LegacySignInResponse]], error) {
	tkn, err := h.AuthServ.Login(ctx, inputs.Body)
	if err != nil {
		return nil, legacyError(ctx, http.StatusUnauthorized, err)
	}
	cookies := h.tokenCookies(tkn.Body.AuthTokens)
	token := ""
	if tkn.Body.AuthTokens != nil {
		token = tkn.Body.AuthTokens.AccessToken
	}
	// u := authDtos.UserFromModel(&tkn.Body.UserData)
	resp := accesstokendtos.LegacySignInResponse{
		SignInResponse: authDtos.SignInResponse{
			User:     &tkn.Body.UserData,
			Token:    token,
			Redirect: false,
		},
		AuthTokens: tkn.Body.AuthTokens,
	}
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201, cookies...), nil
}

// RefreshToken handles POST /refresh.
func (h *AccessTokenHandler) RefreshToken(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.RefreshTokenInput]) (*humatypes.HumaRes[dtos.GResp[accesstokendtos.LegacySignInResponse]], error) {
	tkn, err := h.AuthServ.ResetToken(ctx, inputs.Body.Token)
	if err != nil {
		return nil, legacyError(ctx, http.StatusUnauthorized, err)
	}
	cookies := h.tokenCookies(tkn.Body.AuthTokens)
	token := ""
	if tkn.Body.AuthTokens != nil {
		token = tkn.Body.AuthTokens.AccessToken
	}
	// u := authDtos.UserFromModel(&tkn.Body.UserData)
	resp := accesstokendtos.LegacySignInResponse{
		SignInResponse: authDtos.SignInResponse{
			User:     &tkn.Body.UserData,
			Token:    token,
			Redirect: false,
		},
		AuthTokens: tkn.Body.AuthTokens,
	}
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201, cookies...), nil
}

// legacyError keeps the legacy routes' status (400 sign-up / 401 login and refresh) for expected errors,
// while unexpected ones (repository/driver errors) become a logged 500 that does not show the cause.
func legacyError(ctx context.Context, status int, err error) error {
	if ae := autherr.AsAuthError(err); ae != nil && ae.StatusCode > 0 && ae.StatusCode < http.StatusInternalServerError {
		return humatypes.NewError(status, ae.Message)
	}
	return autherr.Internal(ctx, err)
}
