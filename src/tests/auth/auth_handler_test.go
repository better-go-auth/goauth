package auth_test

import (
	"context"
	"testing"

	access_dto "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/tests/helpers"
)

// TestAuthHandler_FullFlow invokes the Auth handlers directly in-process
// without HTTP networking, enabling direct line-by-line debugging of handlers and services.
func TestAuthHandler_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ctx := context.Background()

	email := "direct_handler_user@example.com"
	initialPassword := "securePassword123!"

	var token string
	var accessToken string
	var refreshToken string
	var activeRefreshToken string

	t.Run("01 Sign Up", func(t *testing.T) {
		signUpInput := models.RegisterClientInput{
			FirstName: "John",
			LastName:  "Doe",
			Email:     email,
			Password:  initialPassword,
		}
		resp, err := env.AuthHandler.Register(ctx, &humatypes.HumaReqBody[models.RegisterClientInput]{
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
		if err := env.DB.Model(&models.User{}).Where("email = ?", email).Updates(map[string]any{
			"email_verified": true,
			"active":         true,
		}).Error; err != nil {
			t.Fatalf("Failed to verify user: %v", err)
		}
	})

	t.Run("03 Success: User Login", func(t *testing.T) {
		loginInput := access_dto.LoginData{
			LoginInfo: email,
			Password:  initialPassword,
		}
		resp, err := env.AuthHandler.Login(ctx, &humatypes.HumaReqBody[access_dto.LoginData]{
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
		activeRefreshToken = refreshToken
		if accessToken == "" || refreshToken == "" {
			t.Fatalf("Expected non-empty tokens, got access=%q, refresh=%q", accessToken, refreshToken)
		}
	})

	t.Run("04 Refresh Token", func(t *testing.T) {
		refreshInput := access_dto.RefreshTokenInput{
			Token: refreshToken,
		}
		resp, err := env.AuthHandler.RefreshToken(ctx, &humatypes.HumaReqBody[access_dto.RefreshTokenInput]{
			Body: refreshInput,
		})
		if err != nil {
			t.Fatalf("RefreshToken handler failed: %v", err)
		}
		if resp == nil || resp.Body.Body.AuthTokens == nil {
			t.Fatalf("Expected new AuthTokens in refresh response, got nil")
		}
		activeRefreshToken = resp.Body.Body.AuthTokens.RefreshToken
	})

	t.Run("05 Logout", func(t *testing.T) {
		resp, err := env.AuthHandler.Logout(ctx, &humatypes.HumaReqBody[access_dto.RefreshTokenInput]{
			Body: access_dto.RefreshTokenInput{
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
