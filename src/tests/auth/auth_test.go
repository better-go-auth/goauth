package auth_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	auth "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/better-go-auth/goauth/src/common/dtos"
)

func TestAuthE2E_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t,true)

	email := "e2e_user@example.com"
	initialPassword := "securePassword123!"
	var token string
	var accessToken string
	var refreshToken string

	t.Run("Sign Up", func(t *testing.T) {
		signUpInput := models.RegisterClientInput{
			FirstName: "John",
			LastName:  "Doe",
			Email:     email,
			Password:  initialPassword,
		}
		resp, body := env.PostJSON("/api/auth/signup", signUpInput)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			t.Fatalf("SignUp failed: status %d, body: %s", resp.StatusCode, body)
		}

		var ok bool
		token, ok = env.MockEmail.LastToken(email)
		if !ok || token == "" {
			t.Fatalf("Expected verification code to be sent to %s, but none was recorded", email)
		}
	})

	t.Run("Verify Email", func(t *testing.T) {
		if err := env.DB.Model(&models.User{}).Where("email = ?", email).Updates(map[string]any{
			"email_verified": true,
			"active":         true,
		}).Error; err != nil {
			t.Fatalf("Failed to verify user: %v", err)
		}
	})

	t.Run("Success: User Login", func(t *testing.T) {
		loginInput := auth.LoginData{
			LoginInfo: email,
			Password:  initialPassword,
		}
		resp, body := env.PostJSON("/api/auth/login", loginInput)
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

	t.Run("Refresh Token", func(t *testing.T) {
		refreshInput := auth.RefreshTokenInput{
			Token: refreshToken,
		}
		resp, body := env.PostJSON("/api/auth/refresh", refreshInput)
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
		accessToken = refreshResp.Body.AuthTokens.AccessToken
	})

	t.Run("Logout", func(t *testing.T) {
		resp, body := env.PostJSON("/api/auth/sign-out", nil, map[string]string{
			"Authorization": "Bearer " + accessToken,
			"Origin":        env.BaseURL,
		})
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("SignOut failed: status %d, body: %s", resp.StatusCode, body)
		}

		// Verify access token is blacklisted and rejected on subsequent requests
		getSessResp, sessBody := env.GetJSON("/api/auth/get-session", map[string]string{
			"Authorization": "Bearer " + accessToken,
		})
		if getSessResp.StatusCode == http.StatusOK && strings.Contains(sessBody, "userId") {
			t.Fatalf("expected get-session to not return session data after sign-out, got: %s", sessBody)
		}
	})
}

func isSuccess(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated
}
