package auth_test

import (
	"context"
	"testing"

	"github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/birukbelay/gocmn/src/dtos"
)

// TestAuthHandler_FullFlow invokes the Auth handlers directly in-process
// without HTTP networking, enabling direct line-by-line debugging of handlers and services.
func TestAuthHandler_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ctx := context.Background()

	email := "direct_handler_user@example.com"
	initialPassword := "securePassword123!"
	newPassword := "updatedPassword456!"

	var token string
	var accessToken string
	var refreshToken string
	var resetCode string
	var activeRefreshToken string

	t.Run("01 Sign Up", func(t *testing.T) {
		signUpInput := models.RegisterClientInput{
			FirstName: "John",
			LastName:  "Doe",
			Email:     email,
			Password:  initialPassword,
		}
		resp, err := env.AuthHandler.Register(ctx, &dtos.HumaReqBody[models.RegisterClientInput]{
			Body: signUpInput,
		})
		if err != nil {
			t.Fatalf("Register handler failed: %v", err)
		}
		if resp == nil || resp.Body.Body.User == nil {
			t.Fatalf("Unexpected register response: %+v", resp)
		}

		var ok bool
		token, ok = env.MockEmail.LastToken(email)
		if !ok || token == "" {
			t.Fatalf("Expected verification token sent to %s, got none", email)
		}
	})

	t.Run("02 Verify Email", func(t *testing.T) {
		verifyInput := auth.VerificationInput{
			Info: email,
			Code: token,
		}
		resp, err := env.AuthHandler.VerifyRegisteredAccount(ctx, &dtos.HumaReqBody[auth.VerificationInput]{
			Body: verifyInput,
		})
		if err != nil {
			t.Fatalf("VerifyRegisteredAccount handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Body.Status {
			t.Fatalf("Expected successful verification, got %+v", resp)
		}
	})

	t.Run("03 Success: User Login", func(t *testing.T) {
		loginInput := auth.LoginData{
			LoginInfo: email,
			Password:  initialPassword,
		}
		resp, err := env.AuthHandler.Login(ctx, &dtos.HumaReqBody[auth.LoginData]{
			Body: loginInput,
		})
		if err != nil {
			t.Fatalf("Login handler failed: %v", err)
		}
		if resp == nil || resp.Body.Body.AuthTokens == nil {
			t.Fatalf("Expected AuthTokens in login response, got nil")
		}

		accessToken = resp.Body.Body.AuthTokens.AccessToken
		refreshToken = resp.Body.Body.AuthTokens.RefreshToken
		if accessToken == "" || refreshToken == "" {
			t.Fatalf("Expected non-empty tokens, got access=%q, refresh=%q", accessToken, refreshToken)
		}
	})

	t.Run("04 Refresh Token", func(t *testing.T) {
		refreshInput := auth.RefreshTokenInput{
			Token: refreshToken,
		}
		resp, err := env.AuthHandler.RefreshToken(ctx, &dtos.HumaReqBody[auth.RefreshTokenInput]{
			Body: refreshInput,
		})
		if err != nil {
			t.Fatalf("RefreshToken handler failed: %v", err)
		}
		if resp == nil || resp.Body.Body.AuthTokens == nil {
			t.Fatalf("Expected new AuthTokens in refresh response, got nil")
		}
	})

	t.Run("05 Forgot Password Request", func(t *testing.T) {
		forgotInput := auth.VerifyReqInput{
			Email: email,
		}
		resp, err := env.AuthHandler.ForgotPwd(ctx, &dtos.HumaReqBody[auth.VerifyReqInput]{
			Body: forgotInput,
		})
		if err != nil {
			t.Fatalf("ForgotPwd handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}

		var ok bool
		resetCode, ok = env.MockEmail.LastToken(email)
		if !ok || resetCode == "" {
			t.Fatalf("Expected password reset code, got none")
		}
	})

	t.Run("06 Reset Password", func(t *testing.T) {
		resetInput := auth.PwdResetInput{
			Info:        email,
			Code:        resetCode,
			NewPassword: newPassword,
		}
		resp, err := env.AuthHandler.ResetPwd(ctx, &dtos.HumaReqBody[auth.PwdResetInput]{
			Body: resetInput,
		})
		if err != nil {
			t.Fatalf("ResetPwd handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}
	})

	t.Run("07 Verify Old Password Fails", func(t *testing.T) {
		_, err := env.AuthHandler.Login(ctx, &dtos.HumaReqBody[auth.LoginData]{
			Body: auth.LoginData{
				LoginInfo: email,
				Password:  initialPassword,
			},
		})
		if err == nil {
			t.Fatalf("Expected login with old password to fail, but succeeded")
		}
	})

	t.Run("08 Verify New Password Login", func(t *testing.T) {
		resp, err := env.AuthHandler.Login(ctx, &dtos.HumaReqBody[auth.LoginData]{
			Body: auth.LoginData{
				LoginInfo: email,
				Password:  newPassword,
			},
		})
		if err != nil {
			t.Fatalf("Login with new password failed: %v", err)
		}
		if resp == nil || resp.Body.Body.AuthTokens == nil {
			t.Fatalf("Expected AuthTokens in login response, got nil")
		}
		activeRefreshToken = resp.Body.Body.AuthTokens.RefreshToken
	})

	t.Run("09 Logout", func(t *testing.T) {
		resp, err := env.AuthHandler.Logout(ctx, &dtos.HumaReqBody[auth.RefreshTokenInput]{
			Body: auth.RefreshTokenInput{
				Token: activeRefreshToken,
			},
		})
		if err != nil {
			t.Fatalf("Logout handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Body.Success {
			t.Fatalf("Expected success true on logout, got %+v", resp)
		}
	})
}
