package profile_test

import (
	"context"
	"testing"

	auth "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/better-go-auth/goauth/src/tests/helpers"
)

// TestProfileHandler_FullFlow invokes the Profile handlers directly in-process
// without HTTP networking, enabling direct line-by-line debugging of handlers and services.
func TestProfileHandler_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ctx := context.Background()

	email := "handler_profile_user@example.com"
	password := "initialPassword123!"
	newPassword := "newSecretPassword456!"
	newEmail := "janet.handler.new@example.com"

	var userID string
	var sessionID string
	var authCtx context.Context
	var reAuthCtx context.Context
	var changeCode string

	t.Run("01 Sign Up and Verify Email", func(t *testing.T) {
		regResp, err := env.AuthHandler.Register(ctx, &humatypes.HumaReqBody[models.RegisterClientInput]{
			Body: models.RegisterClientInput{
				FirstName: "Jane",
				LastName:  "Doe",
				Email:     email,
				Password:  password,
			},
		})
		if err != nil {
			t.Fatalf("Register failed: %v", err)
		}
		_ = regResp

		if err := env.DB.Model(&models.User{}).Where("email = ?", email).Updates(map[string]any{
			"email_verified": true,
			"active":         true,
		}).Error; err != nil {
			t.Fatalf("Failed to verify user: %v", err)
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

	t.Run("03 Get My Profile", func(t *testing.T) {
		resp, err := env.ProfileHandler.GetMyProfile(authCtx, nil)
		if err != nil {
			t.Fatalf("GetMyProfile handler failed: %v", err)
		}
		if resp == nil || resp.Body.Body.FirstName != "Jane" {
			t.Fatalf("Expected firstName 'Jane', got %+v", resp)
		}
	})

	t.Run("04 Update My Profile", func(t *testing.T) {
		updateInput := models.ProfileUpdateDto{
			FirstName: "Janet",
			LastName:  "Smith",
		}
		resp, err := env.ProfileHandler.UpdateMyProfile(authCtx, &humatypes.HumaReqBody[models.ProfileUpdateDto]{
			Body: updateInput,
		})
		if err != nil {
			t.Fatalf("UpdateMyProfile handler failed: %v", err)
		}
		if resp == nil || resp.Body.Body.FirstName != "Janet" {
			t.Fatalf("Expected firstName 'Janet', got %+v", resp)
		}
	})

	t.Run("05 Change Password", func(t *testing.T) {
		changePwdInput := models.PasswordUpdateDto{
			OldPassword: password,
			NewPassword: newPassword,
		}
		_, err := env.ProfileHandler.UpdateMyPassword(authCtx, &humatypes.HumaReqBody[models.PasswordUpdateDto]{
			Body: changePwdInput,
		})
		if err != nil {
			t.Fatalf("UpdateMyPassword handler failed: %v", err)
		}

		// Verify old password fails
		_, err = env.AuthHandler.Login(ctx, &humatypes.HumaReqBody[auth.LoginData]{
			Body: auth.LoginData{
				LoginInfo: email,
				Password:  password,
			},
		})
		if err == nil {
			t.Fatalf("Expected login with old password to fail")
		}

		// Verify new password succeeds
		reLoginResp, err := env.AuthHandler.Login(ctx, &humatypes.HumaReqBody[auth.LoginData]{
			Body: auth.LoginData{
				LoginInfo: email,
				Password:  newPassword,
			},
		})
		if err != nil {
			t.Fatalf("Login with new password failed: %v", err)
		}

		claims, err := jwttoken.ValidateToken(reLoginResp.Body.Body.AuthTokens.AccessToken, helpers.TestAccessSecret)
		if err != nil {
			t.Fatalf("Failed to parse token claims after password change: %v", err)
		}
		reAuthCtx = helpers.AuthContext(userID, claims.SessionID, string(enums.User))
	})

	t.Run("06 Request Change Email", func(t *testing.T) {
		changeEmailReq := models.ChangeEmailReqDto{
			Password: newPassword,
			NewEmail: newEmail,
		}
		resp, err := env.ProfileHandler.UpdateMyEmailReq(reAuthCtx, &humatypes.HumaReqBody[models.ChangeEmailReqDto]{
			Body: changeEmailReq,
		})
		if err != nil {
			t.Fatalf("UpdateMyEmailReq handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Body {
			t.Fatalf("Expected status true, got %+v", resp)
		}

		var ok bool
		changeCode, ok = env.MockEmail.LastToken(newEmail)
		if !ok || changeCode == "" {
			t.Fatalf("Expected change email code sent to %s, got none", newEmail)
		}
	})

	t.Run("07 Verify Change Email", func(t *testing.T) {
		verifyChangeEmailReq := models.VerifyEmailDto{
			Code:     changeCode,
			NewEmail: newEmail,
		}
		resp, err := env.ProfileHandler.UpdateMyEmailVerify(reAuthCtx, &humatypes.HumaReqBody[models.VerifyEmailDto]{
			Body: verifyChangeEmailReq,
		})
		if err != nil {
			t.Fatalf("UpdateMyEmailVerify handler failed: %v", err)
		}
		if resp == nil || resp.Body.Body.Email != newEmail {
			t.Fatalf("Expected updated email %s, got %+v", newEmail, resp)
		}
	})

	t.Run("08 Login with New Email", func(t *testing.T) {
		resp, err := env.AuthHandler.Login(ctx, &humatypes.HumaReqBody[auth.LoginData]{
			Body: auth.LoginData{
				LoginInfo: newEmail,
				Password:  newPassword,
			},
		})
		if err != nil {
			t.Fatalf("Login with new email failed: %v", err)
		}
		if resp == nil || resp.Body.Body.AuthTokens == nil {
			t.Fatalf("Expected AuthTokens in login response, got nil")
		}
	})
}
