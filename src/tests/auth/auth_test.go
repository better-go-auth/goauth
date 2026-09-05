package auth_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/birukbelay/gocmn/src/dtos"
)

func TestAuthE2E_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t)

	email := "e2e_user@example.com"
	initialPassword := "securePassword123!"

	// 1. Sign up
	signUpInput := models.RegisterClientInput{
		FirstName: "John",
		LastName:  "Doe",
		Email:     email,
		Password:  initialPassword,
	}
	resp, body := env.PostJSON("/api/v1/01-auth/signup", signUpInput)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("SignUp failed: status %d, body: %s", resp.StatusCode, body)
	}

	// 2. Retrieve verification code from mock email
	token, ok := env.MockEmail.LastToken(email)
	if !ok || token == "" {
		t.Fatalf("Expected verification code to be sent to %s, but none was recorded", email)
	}

	// 3. Verify email
	verifyInput := auth.VerificationInput{
		Info: email,
		Code: token,
	}
	resp, body = env.PostJSON("/api/v1/01-auth/verify", verifyInput)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("Verify failed: status %d, body: %s", resp.StatusCode, body)
	}
	var accessToken string
	var refreshToken string

	t.Run("Success: User Login", func(t *testing.T) {
		// 4. Login
		loginInput := auth.LoginData{
			LoginInfo: email,
			Password:  initialPassword,
		}
		resp, body = env.PostJSON("/api/v1/01-auth/login", loginInput)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("Login failed: status %d, body: %s", resp.StatusCode, body)
		}

		t.Logf("Login body: %s", body)
		var loginResp dtos.GResp[authDtos.SignInResponse]
		if err := json.Unmarshal([]byte(body), &loginResp); err != nil {
			t.Fatalf("Failed to decode login response: %v, raw body: %s", err, body)
		}

		if loginResp.Body.AuthTokens == nil {
			t.Fatalf("Expected AuthTokens in login response, got nil (loginResp: %+v)", loginResp)
		}

		accessToken = loginResp.Body.AuthTokens.AccessToken
		refreshToken = loginResp.Body.AuthTokens.RefreshToken
		if accessToken == "" || refreshToken == "" {
			t.Fatalf("Tokens must not be empty: access=%q, refresh=%q", accessToken, refreshToken)
		}

	})

	// 5. Refresh token
	refreshInput := auth.RefreshTokenInput{
		Token: refreshToken,
	}
	resp, body = env.PostJSON("/api/v1/01-auth/refresh", refreshInput)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("RefreshToken failed: status %d, body: %s", resp.StatusCode, body)
	}

	var refreshResp dtos.GResp[authDtos.SignInResponse]
	if err := json.Unmarshal([]byte(body), &refreshResp); err != nil {
		t.Fatalf("Failed to decode refresh response: %v, raw body: %s", err, body)
	}

	if refreshResp.Body.AuthTokens == nil {
		t.Fatalf("Expected new AuthTokens in refresh response, got nil")
	}
	_ = refreshResp.Body.AuthTokens.RefreshToken

	// 6. Forgot password
	forgotInput := auth.VerifyReqInput{
		Email: email,
	}
	resp, body = env.PostJSON("/api/v1/01-auth/forgot_password", forgotInput)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("ForgotPwd failed: status %d, body: %s", resp.StatusCode, body)
	}

	resetCode, ok := env.MockEmail.LastToken(email)
	if !ok || resetCode == "" {
		t.Fatalf("Expected password reset code, got none")
	}

	// 7. Reset password
	newPassword := "updatedPassword456!"
	resetInput := auth.PwdResetInput{
		Info:        email,
		Code:        resetCode,
		NewPassword: newPassword,
	}
	resp, body = env.PostJSON("/api/v1/01-auth/reset_password", resetInput)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("ResetPwd failed: status %d, body: %s", resp.StatusCode, body)
	}

	// 8. Verify old password no longer works
	resp, _ = env.PostJSON("/api/v1/01-auth/login", auth.LoginData{
		LoginInfo: email,
		Password:  initialPassword,
	})
	if isSuccess(resp.StatusCode) {
		t.Fatalf("Expected login with old password to fail, but got status %d", resp.StatusCode)
	}

	// 9. Verify new password works
	resp, body = env.PostJSON("/api/v1/01-auth/login", auth.LoginData{
		LoginInfo: email,
		Password:  newPassword,
	})
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("Expected login with new password to succeed, got status %d, body: %s", resp.StatusCode, body)
	}

	var postResetLoginResp dtos.GResp[authDtos.SignInResponse]
	if err := json.Unmarshal([]byte(body), &postResetLoginResp); err != nil {
		t.Fatalf("Failed to decode post-reset login response: %v", err)
	}
	if postResetLoginResp.Body.AuthTokens == nil {
		t.Fatalf("Expected AuthTokens in post-reset login response, got nil")
	}
	activeRefreshToken := postResetLoginResp.Body.AuthTokens.RefreshToken

	// 10. Logout
	logoutInput := auth.RefreshTokenInput{
		Token: activeRefreshToken,
	}
	resp, body = env.PostJSON("/api/v1/01-auth/logout", logoutInput)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("Logout failed: status %d, body: %s", resp.StatusCode, body)
	}
}

func isSuccess(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated
}
