package humaaccesstoken

import (
	"context"
	"net/http"
	"time"

	Icnst "github.com/better-go-auth/goauth/src/common"
	"github.com/better-go-auth/goauth/src/common/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	services "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
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
func (h *AccessTokenHandler) tokenCookies(tokens *models.AuthTokens) []http.Cookie {
	if tokens == nil {
		return nil
	}
	accessExpiry := h.Config.JWT.AccessExpiresIn
	refreshExpiry := h.Cookies.RefreshMaxAge
	if refreshExpiry <= 0 {
		refreshExpiry = 7 * 24 * time.Hour
	}
	return []http.Cookie{
		CreateCookie(Icnst.AccessToken, tokens.AccessToken, accessExpiry, h.Cookies),
		CreateCookie(Icnst.RefreshToken, tokens.RefreshToken, refreshExpiry, h.Cookies),
	}
}

// Register handles POST /signup.
func (h *AccessTokenHandler) Register(ctx context.Context, inputs *humatypes.HumaReqBody[models.RegisterClientInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.SignUpResponse]], error) {
	usr, err := h.AuthServ.RegisterWithEmail(ctx, inputs.Body)
	if err != nil {
		return nil, humatypes.NewError(http.StatusBadRequest, err.Error())
	}

	resp := authDtos.SignUpResponse{
		User:  &usr.User,
		Token: nil,
	}
	gresp := dtos.SuccessCreated(resp, 1)
	return humatypes.MakeResPtr(&gresp, 200), nil
}


// Login handles POST /login.
func (h *AccessTokenHandler) Login(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.LoginData]) (*humatypes.HumaRes[dtos.GResp[authDtos.SignInResponse]], error) {
	tkn, err := h.AuthServ.Login(ctx, inputs.Body)
	if err != nil {
		return nil, humatypes.NewError(http.StatusUnauthorized, err.Error())
	}
	cookies := h.tokenCookies(tkn.Body.AuthTokens)
	token := ""
	if tkn.Body.AuthTokens != nil {
		token = tkn.Body.AuthTokens.AccessToken
	}
	// u := authDtos.UserFromModel(&tkn.Body.UserData)
	resp := authDtos.SignInResponse{
		User:       &tkn.Body.UserData,
		Token:      token,
		Redirect:   false,
		AuthTokens: tkn.Body.AuthTokens,
	}
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201, cookies...), nil
}

// RefreshToken handles POST /refresh.
func (h *AccessTokenHandler) RefreshToken(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.RefreshTokenInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.SignInResponse]], error) {
	tkn, err := h.AuthServ.ResetToken(ctx, inputs.Body.Token)
	if err != nil {
		return nil, humatypes.NewError(http.StatusUnauthorized, err.Error())
	}
	cookies := h.tokenCookies(tkn.Body.AuthTokens)
	token := ""
	if tkn.Body.AuthTokens != nil {
		token = tkn.Body.AuthTokens.AccessToken
	}
	// u := authDtos.UserFromModel(&tkn.Body.UserData)
	resp := authDtos.SignInResponse{
		User:       &tkn.Body.UserData,
		Token:      token,
		Redirect:   false,
		AuthTokens: tkn.Body.AuthTokens,
	}
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201, cookies...), nil
}



// VerifyRegisteredAccount handles POST /verify.
// func (h *AccessTokenHandler) VerifyRegisteredAccount(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.VerificationInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.VerifyEmailResponse]], error) {
// 	usr, err := h.AuthServ.VerifyRegisteredUser(ctx, inputs.Body)
// 	if err != nil {
// 		return nil, humatypes.NewError(http.StatusBadRequest, err.Error())
// 	}
// 	u := authDtos.UserFromModel(&usr.Body)
// 	resp := authDtos.VerifyEmailResponse{
// 		User:   &u,
// 		Status: true,
// 	}
// 	gresp := dtos.SuccessCreated(resp, usr.RowsAffected)
// 	return humatypes.MakeRes(gresp, 200), nil
// }