package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/common/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"

	"github.com/danielgtaylor/huma/v2"

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

func (ah *GinAuthHandler) Register(ctx context.Context, inputs *humatypes.HumaReqBody[models.RegisterClientInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.SignUpResponse]], error) {
	usr, err := ah.AdminAuthServ.RegisterWithEmail(ctx, inputs.Body)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	resp := authDtos.SignUpResponse{
		User:  authDtos.UserToResponse(&usr.Body),
		Token: nil,
	}
	gresp := dtos.SuccessCreated(resp, usr.RowsAffected)
	return humatypes.MakeResPtr(&gresp, 200), nil
}

func (ah *GinAuthHandler) VerifyRegisteredAccount(ctx context.Context, inputs *humatypes.HumaReqBody[VerificationInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.VerifyEmailResponse]], error) {
	usr, err := ah.AdminAuthServ.VerifyRegisteredUser(ctx, inputs.Body)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	resp := authDtos.VerifyEmailResponse{
		User:   authDtos.UserToResponse(&usr.Body),
		Status: true,
	}
	gresp := dtos.SuccessCreated(resp, usr.RowsAffected)
	return humatypes.MakeRes(gresp, 200), nil
}

func (ah *GinAuthHandler) Login(ctx context.Context, inputs *humatypes.HumaReqBody[LoginData]) (*humatypes.HumaRes[dtos.GResp[authDtos.SignInResponse]], error) {
	tkn, err := ah.AdminAuthServ.Login(ctx, inputs.Body)
	if err != nil {
		return nil, huma.NewError(http.StatusUnauthorized, err.Error())
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
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201, cookies...), nil
}

func (ah *GinAuthHandler) RefreshToken(ctx context.Context, inputs *humatypes.HumaReqBody[RefreshTokenInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.SignInResponse]], error) {
	tkn, err := ah.AdminAuthServ.ResetToken(ctx, inputs.Body.Token)
	if err != nil {
		return nil, huma.NewError(http.StatusUnauthorized, err.Error())
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
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201, cookies...), nil
}

func (ah *GinAuthHandler) Logout(ctx context.Context, inputs *humatypes.HumaReqBody[RefreshTokenInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.SuccessResponse]], error) {
	tkn, err := ah.AdminAuthServ.Logout(ctx, inputs.Body.Token)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	resp := authDtos.SuccessResponse{
		Success: tkn.Body,
	}
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201), nil
}

func (ah *GinAuthHandler) ForgotPwd(ctx context.Context, inputs *humatypes.HumaReqBody[VerifyReqInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.StatusResponse]], error) {
	tkn, err := ah.AdminAuthServ.ForgotPwd(ctx, inputs.Body)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	resp := authDtos.StatusResponse{
		Status:  tkn.Body,
		Message: "Password reset verification code sent",
	}
	return humatypes.MakeRes(dtos.SuccessCreated(resp, tkn.RowsAffected), 201), nil
}

func (ah *GinAuthHandler) ResetPwd(ctx context.Context, inputs *humatypes.HumaReqBody[PwdResetInput]) (*humatypes.HumaRes[dtos.GResp[authDtos.StatusResponse]], error) {
	tkn, err := ah.AdminAuthServ.ResetPwd(ctx, inputs.Body)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
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
