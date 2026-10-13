package humaaccesstoken

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	Icnst "github.com/better-go-auth/goauth/src/common"
	"github.com/better-go-auth/goauth/src/common/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	services "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
)

// AccessTokenHandler provides Huma handlers for access-token / JWT flows.
type AccessTokenHandler struct {
	AuthServ    services.IAccessTokenAuthService
	SessionServ services.IAccessTokenSessionService
	ProfileServ services.IAccessTokenProfileService
	SessionRepo repo_interfaces.ISessionRepo
	Config      *config.SessionGoAuth
	Cookies     CookieAttrs
}

func (h *AccessTokenHandler) tokenCookies(tokens *models.AuthTokens) []http.Cookie {
	if tokens == nil {
		return nil
	}
	accessExpiry := h.Config.JWT.AccessExpiresIn
	refreshExpiry := h.Cookies.RefreshMaxAge
	if refreshExpiry <= 0 {
		refreshExpiry = h.Config.JWT.RefreshExpiresIn
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

// VerifyRegisteredAccount handles POST /verify.
func (h *AccessTokenHandler) VerifyRegisteredAccount(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.VerificationInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.VerifyEmailResponse]], error) {
	usr, err := h.AuthServ.VerifyRegisteredUser(ctx, inputs.Body)
	if err != nil {
		return nil, humatypes.NewError(http.StatusBadRequest, err.Error())
	}
	u := authDtos.UserFromModel(&usr.Body)
	resp := authDtos.VerifyEmailResponse{
		User:   &u,
		Status: true,
	}
	gresp := dtos.SuccessCreated(resp, usr.RowsAffected)
	return humatypes.MakeRes(gresp, 200), nil
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

// Logout handles POST /logout.
func (h *AccessTokenHandler) Logout(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.RefreshTokenInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.SuccessResponse]], error) {
	tkn, err := h.AuthServ.Logout(ctx, inputs.Body.Token)
	if err != nil {
		return nil, humatypes.NewError(http.StatusBadRequest, err.Error())
	}
	resp := authDtos.SuccessResponse{
		Success: tkn.Body,
	}
	cookies := []http.Cookie{
		ExpireCookie(Icnst.AccessToken, h.Cookies),
		ExpireCookie(Icnst.RefreshToken, h.Cookies),
	}
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201, cookies...), nil
}

// ForgotPwd handles POST /forgot_password.
func (h *AccessTokenHandler) ForgotPwd(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.VerifyReqInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.StatusResponse]], error) {
	tkn, err := h.AuthServ.ForgotPwd(ctx, inputs.Body)
	if err != nil {
		return nil, humatypes.NewError(http.StatusBadRequest, err.Error())
	}
	resp := authDtos.StatusResponse{
		Status:  tkn.Body,
		Message: "Password reset verification code sent",
	}
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201), nil
}

// ResetPwd handles POST /reset_password.
func (h *AccessTokenHandler) ResetPwd(ctx context.Context, inputs *humatypes.HumaReqBody[accesstokendtos.PwdResetInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.StatusResponse]], error) {
	tkn, err := h.AuthServ.ResetPwd(ctx, inputs.Body)
	if err != nil {
		return nil, humatypes.NewError(http.StatusBadRequest, err.Error())
	}
	resp := authDtos.StatusResponse{
		Status:  tkn.Body,
		Message: "Password reset successfully",
	}
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201), nil
}

// func (ah *GinAuthHandler[T]) ChangeActiveCompany(ctx context.Context, inputs *dtos.HumaReqBody[ChangeActiveCompanyInput]) (*dtos.HumaResponse[dtos.GResp[TokenResponse]], error) {
// 	userID := ctx.Value(consts.CTXUser_ID.Str()).(string)
// 	tkn, err := ah.AdminAuthServ.ChangeActiveCompany(ctx, userID, inputs.Body)
// 	if err != nil {
// 		return dtos.HumaReturnG(tkn, err)
// 	}
// 	refreshCookie := CreateCookie(Icnst.RefreshToken, tkn.Body.AuthTokens.RefreshToken, ah.AdminAuthServ.Config.JwtVar.RefreshExpireMin)
// 	accessCookie := CreateCookie(Icnst.AccessToken, tkn.Body.AuthTokens.AccessToken, ah.AdminAuthServ.Config.JwtVar.AccessExpireMin)
// 	return dtos.HumaReturnGWithCookie(tkn, err, []http.Cookie{refreshCookie, accessCookie})
// }
