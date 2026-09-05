package profile_test

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

func isSuccess(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated
}

func TestProfileE2E_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t)

	email := "profile_user@example.com"
	password := "initialPassword123!"

	// 1. Sign up & verify
	_, _ = env.PostJSON("/api/v1/01-auth/signup", models.RegisterClientInput{
		FirstName: "Jane",
		LastName:  "Doe",
		Email:     email,
		Password:  password,
	})
	token, _ := env.MockEmail.LastToken(email)
	_, _ = env.PostJSON("/api/v1/01-auth/verify", auth.VerificationInput{
		Info: email,
		Code: token,
	})

	// 2. Login
	resp, body := env.PostJSON("/api/v1/01-auth/login", auth.LoginData{
		LoginInfo: email,
		Password:  password,
	})
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("Login failed: status %d, body: %s", resp.StatusCode, body)
	}

	var loginResp dtos.GResp[authDtos.SignInResponse]
	if err := json.Unmarshal([]byte(body), &loginResp); err != nil {
		t.Fatalf("Failed to parse login response: %v", err)
	}
	accessToken := loginResp.Body.AuthTokens.AccessToken
	authHeader := map[string]string{"Authorization": "Bearer " + accessToken}

	// 3. Get profile
	resp, body = env.GetJSON("/api/v1/01-profile", authHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("GetMyProfile failed: status %d, body: %s", resp.StatusCode, body)
	}
	var getProfileResp dtos.GResp[models.User]
	if err := json.Unmarshal([]byte(body), &getProfileResp); err != nil {
		t.Fatalf("Failed to decode profile response: %v, raw: %s", err, body)
	}
	if getProfileResp.Body.FirstName != "Jane" {
		t.Fatalf("Expected firstName 'Jane', got %q", getProfileResp.Body.FirstName)
	}

	// 4. Update profile
	updateInput := models.ProfileUpdateDto{
		FirstName: "Janet",
		LastName:  "Smith",
	}
	resp, body = env.PatchJSON("/api/v1/01-profile", updateInput, authHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("UpdateMyProfile failed: status %d, body: %s", resp.StatusCode, body)
	}
	var updatedProfileResp dtos.GResp[models.User]
	if err := json.Unmarshal([]byte(body), &updatedProfileResp); err == nil && updatedProfileResp.Body.FirstName != "" {
		if updatedProfileResp.Body.FirstName != "Janet" {
			t.Fatalf("Expected firstName 'Janet', got %q", updatedProfileResp.Body.FirstName)
		}
	}

	// 5. Change password
	newPassword := "newSecretPassword456!"
	changePwdInput := models.PasswordUpdateDto{
		OldPassword: password,
		NewPassword: newPassword,
	}
	resp, body = env.PostJSON("/api/v1/01-profile/change_pwd", changePwdInput, authHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("ChangePassword failed: status %d, body: %s", resp.StatusCode, body)
	}

	// Verify old password fails and new password succeeds
	resp, _ = env.PostJSON("/api/v1/01-auth/login", auth.LoginData{
		LoginInfo: email,
		Password:  password,
	})
	if isSuccess(resp.StatusCode) {
		t.Fatalf("Expected login with old password to fail")
	}

	resp, body = env.PostJSON("/api/v1/01-auth/login", auth.LoginData{
		LoginInfo: email,
		Password:  newPassword,
	})
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("Login with changed password failed: status %d, body: %s", resp.StatusCode, body)
	}
	var reLoginResp dtos.GResp[authDtos.SignInResponse]
	_ = json.Unmarshal([]byte(body), &reLoginResp)
	reAuthHeader := map[string]string{"Authorization": "Bearer " + reLoginResp.Body.AuthTokens.AccessToken}

	// 6. Request Change Email
	newEmail := "janet.new@example.com"
	changeEmailReq := models.ChangeEmailReqDto{
		Password: newPassword,
		NewEmail: newEmail,
	}
	resp, body = env.PostJSON("/api/v1/01-profile/change_email", changeEmailReq, reAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("UpdateMyEmailReq failed: status %d, body: %s", resp.StatusCode, body)
	}

	changeCode, ok := env.MockEmail.LastToken(newEmail)
	if !ok || changeCode == "" {
		t.Fatalf("Expected change email code sent to %s, got none", newEmail)
	}

	// 7. Verify Change Email
	verifyChangeEmailReq := models.VerifyEmailDto{
		Code:     changeCode,
		NewEmail: newEmail,
	}
	resp, body = env.PostJSON("/api/v1/01-profile/verify_change_email", verifyChangeEmailReq, reAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("VerifyMyChangeEmailReq failed: status %d, body: %s", resp.StatusCode, body)
	}

	// 8. Verify login with new email succeeds
	resp, body = env.PostJSON("/api/v1/01-auth/login", auth.LoginData{
		LoginInfo: newEmail,
		Password:  newPassword,
	})
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("Login with new email failed: status %d, body: %s", resp.StatusCode, body)
	}
}
