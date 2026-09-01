package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/birukbelay/gocmn/src/dtos"

	Icnst "github.com/better-go-auth/goauth/src/common"
	"github.com/better-go-auth/goauth/src/models"
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

func (ah *GinAuthHandler[T]) Register(ctx context.Context, inputs *dtos.HumaReqBody[models.RegisterClientInput]) (*dtos.HumaResponse[dtos.GResp[bool]], error) {
	usr, err := ah.AdminAuthServ.Register(ctx, inputs.Body)
	return dtos.HumaReturnG(usr, err)
}
func (ah *GinAuthHandler[T]) VerifyRegisteredAccount(ctx context.Context, inputs *dtos.HumaReqBody[VerificationInput]) (*dtos.HumaResponse[dtos.GResp[bool]], error) {
	usr, err := ah.AdminAuthServ.VerifyRegisteredUser(ctx, inputs.Body)
	return dtos.HumaReturnG(usr, err)
}
func (ah *GinAuthHandler[T]) Login(ctx context.Context, inputs *dtos.HumaReqBody[LoginData]) (*dtos.HumaResponse[dtos.GResp[TokenResponse]], error) {
	tkn, err := ah.AdminAuthServ.Login(ctx, inputs.Body)
	if err != nil {
		return dtos.HumaReturnG(tkn, err)
	}
	refreshCookie := CreateCookie(Icnst.RefreshToken, tkn.Body.AuthTokens.RefreshToken, ah.AdminAuthServ.Config.JwtVar.RefreshExpireMin)
	accessCookie := CreateCookie(Icnst.AccessToken, tkn.Body.AuthTokens.AccessToken, ah.AdminAuthServ.Config.JwtVar.AccessExpireMin)
	return dtos.HumaReturnGWithCookie(tkn, err, []http.Cookie{refreshCookie, accessCookie})
}

func (ah *GinAuthHandler[T]) RefreshToken(ctx context.Context, inputs *dtos.HumaReqBody[RefreshTokenInput]) (*dtos.HumaResponse[dtos.GResp[TokenResponse]], error) {
	tkn, err := ah.AdminAuthServ.ResetToken(ctx, inputs.Body.Token)
	refreshCookie := CreateCookie(Icnst.RefreshToken, tkn.Body.AuthTokens.RefreshToken, ah.AdminAuthServ.Config.JwtVar.RefreshExpireMin)
	accessCookie := CreateCookie(Icnst.AccessToken, tkn.Body.AuthTokens.AccessToken, ah.AdminAuthServ.Config.JwtVar.AccessExpireMin)
	return dtos.HumaReturnGWithCookie(tkn, err, []http.Cookie{accessCookie, refreshCookie})
}

func (ah *GinAuthHandler[T]) Logout(ctx context.Context, inputs *dtos.HumaReqBody[RefreshTokenInput]) (*dtos.HumaResponse[dtos.GResp[bool]], error) {
	tkn, err := ah.AdminAuthServ.Logout(ctx, inputs.Body.Token)
	return dtos.HumaReturnG(tkn, err)
}

func (ah *GinAuthHandler[T]) ForgotPwd(ctx context.Context, inputs *dtos.HumaReqBody[VerifyReqInput]) (*dtos.HumaResponse[dtos.GResp[bool]], error) {
	tkn, err := ah.AdminAuthServ.ForgotPwd(ctx, inputs.Body)
	return dtos.HumaReturnG(tkn, err)
}

func (ah *GinAuthHandler[T]) ResetPwd(ctx context.Context, inputs *dtos.HumaReqBody[PwdResetInput]) (*dtos.HumaResponse[dtos.GResp[bool]], error) {
	tkn, err := ah.AdminAuthServ.ResetPwd(ctx, inputs.Body)
	return dtos.HumaReturnG(tkn, err)
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
