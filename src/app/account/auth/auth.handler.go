package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/birukbelay/gocmn/src/dtos"

	Icnst "github.com/better-go-auth/goauth/src/common"
	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
)

func CreateCookie(Name, Value string, minutes int) http.Cookie {
	return http.Cookie{
		Name:     Name,
		Value:    Value,
		Expires:  time.Now().Add(time.Minute * time.Duration(minutes)),
		HttpOnly: true, // Set HttpOnly to true to make the cookie accessible only through HTTP requests, not JavaScript
		Path:     "/",
		Domain:   "",
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
}

func (ah *GinAuthHandler) Register(ctx context.Context, inputs *dtos.HumaReqBody[models.RegisterClientInput]) (*dtos.HumaResponse[dtos.GResp[authDtos.SignUpResponse]], error) {
	usr, err := ah.AdminAuthServ.RegisterWithEmail(ctx, inputs.Body)
	if err != nil {
		return dtos.HumaReturnG(dtos.GResp[authDtos.SignUpResponse]{}, err)
	}
	resp := authDtos.SignUpResponse{
		User:  authDtos.UserToResponse(&usr.Body),
		Token: nil,
	}
	return dtos.HumaReturnG(dtos.SuccessS(resp, usr.RowsAffected), nil)
}

func (ah *GinAuthHandler) VerifyRegisteredAccount(ctx context.Context, inputs *dtos.HumaReqBody[VerificationInput]) (*dtos.HumaResponse[dtos.GResp[authDtos.VerifyEmailResponse]], error) {
	usr, err := ah.AdminAuthServ.VerifyRegisteredUser(ctx, inputs.Body)
	if err != nil {
		return dtos.HumaReturnG(dtos.GResp[authDtos.VerifyEmailResponse]{}, err)
	}
	resp := authDtos.VerifyEmailResponse{
		User:   authDtos.UserToResponse(&usr.Body),
		Status: true,
	}
	return dtos.HumaReturnG(dtos.SuccessS(resp, usr.RowsAffected), nil)
}

func (ah *GinAuthHandler) Login(ctx context.Context, inputs *dtos.HumaReqBody[LoginData]) (*dtos.HumaResponse[dtos.GResp[authDtos.SignInResponse]], error) {
	tkn, err := ah.AdminAuthServ.Login(ctx, inputs.Body)
	if err != nil {
		return dtos.HumaReturnG(dtos.GResp[authDtos.SignInResponse]{}, err)
	}
	var cookies []http.Cookie
	if tkn.Body.AuthTokens != nil {
		refreshCookie := CreateCookie(Icnst.RefreshToken, tkn.Body.AuthTokens.RefreshToken, ah.AdminAuthServ.Config.JwtVar.RefreshExpireMin)
		accessCookie := CreateCookie(Icnst.AccessToken, tkn.Body.AuthTokens.AccessToken, ah.AdminAuthServ.Config.JwtVar.AccessExpireMin)
		cookies = append(cookies, refreshCookie, accessCookie)
	}
	token := ""
	if tkn.Body.AuthTokens != nil {
		token = tkn.Body.AuthTokens.AccessToken
	}
	resp := authDtos.SignInResponse{
		User:       authDtos.UserToResponse(&tkn.Body.UserData),
		Token:      token,
		Redirect:   false,
		AuthTokens: tkn.Body.AuthTokens,
	}
	return dtos.HumaReturnGWithCookie(dtos.SuccessS(resp, tkn.RowsAffected), nil, cookies)
}

func (ah *GinAuthHandler) RefreshToken(ctx context.Context, inputs *dtos.HumaReqBody[RefreshTokenInput]) (*dtos.HumaResponse[dtos.GResp[authDtos.SignInResponse]], error) {
	tkn, err := ah.AdminAuthServ.ResetToken(ctx, inputs.Body.Token)
	if err != nil {
		return dtos.HumaReturnG(dtos.GResp[authDtos.SignInResponse]{}, err)
	}
	var cookies []http.Cookie
	if tkn.Body.AuthTokens != nil {
		refreshCookie := CreateCookie(Icnst.RefreshToken, tkn.Body.AuthTokens.RefreshToken, ah.AdminAuthServ.Config.JwtVar.RefreshExpireMin)
		accessCookie := CreateCookie(Icnst.AccessToken, tkn.Body.AuthTokens.AccessToken, ah.AdminAuthServ.Config.JwtVar.AccessExpireMin)
		cookies = append(cookies, accessCookie, refreshCookie)
	}
	token := ""
	if tkn.Body.AuthTokens != nil {
		token = tkn.Body.AuthTokens.AccessToken
	}
	resp := authDtos.SignInResponse{
		User:       authDtos.UserToResponse(&tkn.Body.UserData),
		Token:      token,
		Redirect:   false,
		AuthTokens: tkn.Body.AuthTokens,
	}
	return dtos.HumaReturnGWithCookie(dtos.SuccessS(resp, tkn.RowsAffected), nil, cookies)
}

func (ah *GinAuthHandler) Logout(ctx context.Context, inputs *dtos.HumaReqBody[RefreshTokenInput]) (*dtos.HumaResponse[dtos.GResp[authDtos.SuccessResponse]], error) {
	tkn, err := ah.AdminAuthServ.Logout(ctx, inputs.Body.Token)
	if err != nil {
		return dtos.HumaReturnG(dtos.GResp[authDtos.SuccessResponse]{}, err)
	}
	resp := authDtos.SuccessResponse{
		Success: tkn.Body,
	}
	return dtos.HumaReturnG(dtos.SuccessS(resp, tkn.RowsAffected), nil)
}

func (ah *GinAuthHandler) ForgotPwd(ctx context.Context, inputs *dtos.HumaReqBody[VerifyReqInput]) (*dtos.HumaResponse[dtos.GResp[authDtos.StatusResponse]], error) {
	tkn, err := ah.AdminAuthServ.ForgotPwd(ctx, inputs.Body)
	if err != nil {
		return dtos.HumaReturnG(dtos.GResp[authDtos.StatusResponse]{}, err)
	}
	resp := authDtos.StatusResponse{
		Status:  tkn.Body,
		Message: "Password reset verification code sent",
	}
	return dtos.HumaReturnG(dtos.SuccessS(resp, tkn.RowsAffected), nil)
}

func (ah *GinAuthHandler) ResetPwd(ctx context.Context, inputs *dtos.HumaReqBody[PwdResetInput]) (*dtos.HumaResponse[dtos.GResp[authDtos.StatusResponse]], error) {
	tkn, err := ah.AdminAuthServ.ResetPwd(ctx, inputs.Body)
	if err != nil {
		return dtos.HumaReturnG(dtos.GResp[authDtos.StatusResponse]{}, err)
	}
	resp := authDtos.StatusResponse{
		Status:  tkn.Body,
		Message: "Password reset successfully",
	}
	return dtos.HumaReturnG(dtos.SuccessS(resp, tkn.RowsAffected), nil)
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
