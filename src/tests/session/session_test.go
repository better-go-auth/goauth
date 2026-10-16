package session_test

import (
	"encoding/json"
	"net/http"
	"testing"

	auth "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/better-go-auth/goauth/src/common/dtos"
)

func TestSessionE2E_GetAndDelete(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)

	email := "session_user@example.com"
	password := "password123!"
	var authHeader map[string]string
	var sessionId string

	t.Run("Sign Up and Verify Email", func(t *testing.T) {
		resp, body := env.PostJSON("/api/auth/signup", models.RegisterClientInput{
			FirstName: "Session",
			LastName:  "User",
			Email:     email,
			Password:  password,
		})
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			t.Fatalf("SignUp failed: status %d, body: %s", resp.StatusCode, body)
		}

		if err := env.DB.Model(&models.User{}).Where("email = ?", email).Updates(map[string]any{
			"email_verified": true,
			"active":         true,
		}).Error; err != nil {
			t.Fatalf("Failed to verify user: %v", err)
		}
	})

	t.Run("User Login", func(t *testing.T) {
		resp, body := env.PostJSON("/api/auth/login", auth.LoginData{
			LoginInfo: email,
			Password:  password,
		})
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			t.Fatalf("Login failed: status %d, body: %s", resp.StatusCode, body)
		}

		var loginResp dtos.GResp[authDtos.SignInResponse]
		if err := json.Unmarshal([]byte(body), &loginResp); err != nil {
			t.Fatalf("Failed to parse login response: %v", err)
		}
		if loginResp.Body.AuthTokens == nil {
			t.Fatalf("Expected AuthTokens in login response, got nil")
		}
		accessToken := loginResp.Body.AuthTokens.AccessToken
		authHeader = map[string]string{"Authorization": "Bearer " + accessToken}
	})

	t.Run("Get Active Sessions", func(t *testing.T) {
		resp, body := env.GetJSON("/api/auth/list-sessions", authHeader)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list-sessions failed: status %d, body: %s", resp.StatusCode, body)
		}

		var sessions []authDtos.SessionData
		if err := json.Unmarshal([]byte(body), &sessions); err != nil {
			t.Fatalf("Failed to decode sessions response: %v, raw: %s", err, body)
		}

		if len(sessions) == 0 {
			t.Fatalf("Expected at least 1 active session, got %d", len(sessions))
		}
		sessionId = sessions[0].ID
		if sessionId == "" {
			t.Fatalf("Expected non-empty session ID")
		}
	})

	t.Run("Sign Out Session", func(t *testing.T) {
		resp, body := env.PostJSON("/api/auth/sign-out", nil, map[string]string{
			"Authorization": authHeader["Authorization"],
			"Origin":        env.BaseURL,
		})
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			t.Fatalf("SignOut failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("Verify Sessions Empty", func(t *testing.T) {
		resp, body := env.GetJSON("/api/auth/list-sessions", authHeader)
		if resp.StatusCode == http.StatusOK {
			var afterDeleteResp []authDtos.SessionData
			if err := json.Unmarshal([]byte(body), &afterDeleteResp); err == nil {
				if len(afterDeleteResp) != 0 {
					t.Fatalf("Expected 0 sessions after deletion, got %d", len(afterDeleteResp))
				}
			}
		}
	})
}
