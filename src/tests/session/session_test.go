package session_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/app/core/auth"
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
		resp, body := env.PostJSON("/api/v1/01-auth/signup", models.RegisterClientInput{
			FirstName: "Session",
			LastName:  "User",
			Email:     email,
			Password:  password,
		})
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			t.Fatalf("SignUp failed: status %d, body: %s", resp.StatusCode, body)
		}

		token, ok := env.MockEmail.LastToken(email)
		if !ok || token == "" {
			t.Fatalf("Expected verification token sent to %s, got none", email)
		}

		resp, body = env.PostJSON("/api/v1/01-auth/verify", auth.VerificationInput{
			Info: email,
			Code: token,
		})
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			t.Fatalf("Verify failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("User Login", func(t *testing.T) {
		resp, body := env.PostJSON("/api/v1/01-auth/login", auth.LoginData{
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
		resp, body := env.GetJSON("/api/v1/01-session?page=1&limit=10", authHeader)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GetMySession failed: status %d, body: %s", resp.StatusCode, body)
		}

		var sessionResp dtos.PResp[[]authDtos.SessionData]
		if err := json.Unmarshal([]byte(body), &sessionResp); err != nil {
			t.Fatalf("Failed to decode sessions response: %v, raw: %s", err, body)
		}

		if len(sessionResp.Body) == 0 {
			t.Fatalf("Expected at least 1 active session, got %d", len(sessionResp.Body))
		}
		sessionId = sessionResp.Body[0].ID
		if sessionId == "" {
			t.Fatalf("Expected non-empty session ID")
		}
	})

	t.Run("Delete Session by ID", func(t *testing.T) {
		resp, body := env.PostJSON(fmt.Sprintf("/api/v1/01-session/%s", sessionId), nil, authHeader)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			t.Fatalf("DeleteSession failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("Verify Sessions Empty", func(t *testing.T) {
		resp, body := env.GetJSON("/api/v1/01-session?page=1&limit=10", authHeader)
		if resp.StatusCode == http.StatusOK {
			var afterDeleteResp dtos.PResp[[]authDtos.SessionData]
			if err := json.Unmarshal([]byte(body), &afterDeleteResp); err == nil {
				if len(afterDeleteResp.Body) != 0 {
					t.Fatalf("Expected 0 sessions after deletion, got %d", len(afterDeleteResp.Body))
				}
			}
		}
	})
}
