package session_test

import (
	"context"
	"testing"

	"github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/common/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/better-go-auth/goauth/src/tests/helpers"
)

// TestSessionHandler_GetAndDelete invokes the Session handlers directly in-process
// without HTTP networking, enabling direct line-by-line debugging of handlers and services.
func TestSessionHandler_GetAndDelete(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ctx := context.Background()

	email := "handler_session_user@example.com"
	password := "password123!"

	var userID string
	var sessionID string
	var authCtx context.Context
	var targetSessionID string

	t.Run("01 Sign Up and Verify Email", func(t *testing.T) {
		_, err := env.AuthHandler.Register(ctx, &humatypes.HumaReqBody[models.RegisterClientInput]{
			Body: models.RegisterClientInput{
				FirstName: "Session",
				LastName:  "User",
				Email:     email,
				Password:  password,
			},
		})
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}

		token, ok := env.MockEmail.LastToken(email)
		if !ok || token == "" {
			t.Fatalf("Expected verification token for %s", email)
		}

		_, err = env.AuthHandler.VerifyRegisteredAccount(ctx, &humatypes.HumaReqBody[auth.VerificationInput]{
			Body: auth.VerificationInput{
				Info: email,
				Code: token,
			},
		})
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}
	})

	t.Run("02 User Login", func(t *testing.T) {
		loginResp, err := env.AuthHandler.Login(ctx, &humatypes.HumaReqBody[auth.LoginData]{
			Body: auth.LoginData{
				LoginInfo: email,
				Password:  password,
			},
		})
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if loginResp.Body.Body.User == nil || loginResp.Body.Body.AuthTokens == nil {
			t.Fatalf("Expected User and AuthTokens in login response")
		}

		userID = loginResp.Body.Body.User.ID
		claims, err := jwttoken.ValidateToken(loginResp.Body.Body.AuthTokens.AccessToken, helpers.TestAccessSecret)
		if err != nil {
			t.Fatalf("Failed to parse token claims: %v", err)
		}
		sessionID = claims.SessionID
		authCtx = helpers.AuthContext(userID, sessionID, string(enums.User))
	})

	t.Run("03 Get Active Sessions", func(t *testing.T) {
		resp, err := env.SessionHandler.GetMySession(authCtx, &models.SessionQuery{
			PaginationInput: dtos.PaginationInput{Page: 1, Limit: 10},
		})
		if err != nil {
			t.Fatalf("GetMySession handler failed: %v", err)
		}
		if resp == nil || len(resp.Body.Body) == 0 {
			t.Fatalf("Expected at least 1 active session, got %v", resp)
		}
		targetSessionID = resp.Body.Body[0].ID
		if targetSessionID == "" {
			t.Fatalf("Expected non-empty session ID")
		}
	})

	t.Run("04 Delete Session by ID", func(t *testing.T) {
		delResp, err := env.SessionHandler.DelteMySession(authCtx, &humatypes.HumaReqId{
			ID: targetSessionID,
		})
		if err != nil {
			t.Fatalf("DelteMySession handler failed: %v", err)
		}
		if delResp == nil || !delResp.Body.Body.Status {
			t.Fatalf("Expected successful session deletion, got %+v", delResp)
		}
	})

	t.Run("05 Verify Sessions Empty", func(t *testing.T) {
		resp, err := env.SessionHandler.GetMySession(authCtx, &models.SessionQuery{
			PaginationInput: dtos.PaginationInput{Page: 1, Limit: 10},
		})
		if err != nil {
			t.Fatalf("GetMySession handler failed: %v", err)
		}
		if resp != nil && len(resp.Body.Body) != 0 {
			t.Fatalf("Expected 0 sessions after deletion, got %d", len(resp.Body.Body))
		}
	})
}
