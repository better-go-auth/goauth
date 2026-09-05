package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/oklog/ulid/v2"
)

func isSuccess(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated
}

func ptr[T any](v T) *T {
	return &v
}

func setupAdminUser(t *testing.T, env *helpers.TestEnv) (string, map[string]string) {
	adminUser := &models.User{
		UserDto: models.UserDto{
			FirstName:     "Super",
			LastName:      "Admin",
			Email:         ptr("admin@example.com"),
			EmailVerified: true,
			Role:          enums.Admin,
		},
	}
	if err := env.DB.Create(adminUser).Error; err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}

	sessionID := ulid.Make().String()
	tokens, err := env.Auth.IAuthServices.CreateSession(context.Background(), sessionID, string(enums.Admin), adminUser.ID, nil)
	if err != nil {
		t.Fatalf("Failed to create admin session: %v", err)
	}

	return adminUser.ID, map[string]string{"Authorization": "Bearer " + tokens.AccessToken}
}

func TestAdminE2E_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	_, adminAuthHeader := setupAdminUser(t, env)

	var managedUserID string
	var userSessionID string
	var impersonatedToken string

	t.Run("01 Create User", func(t *testing.T) {
		createInput := admindtos.AdminCreateUserInput{
			Email:    "managed_user@example.com",
			Password: "InitialPassword123!",
			Name:     "Managed User",
			Role:     enums.User,
		}
		resp, body := env.PostJSON("/api/auth/admin/create-user", createInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("CreateUser failed: status %d, body: %s", resp.StatusCode, body)
		}

		var createResp admindtos.AdminUserWrapperResponse
		if err := json.Unmarshal([]byte(body), &createResp); err != nil || createResp.User == nil {
			t.Fatalf("Failed to decode CreateUser response: %v, raw: %s", err, body)
		}
		managedUserID = createResp.User.ID
		if managedUserID == "" {
			t.Fatalf("Expected non-empty managed user ID")
		}
	})

	t.Run("02 List Users", func(t *testing.T) {
		listInput := admindtos.AdminListUsersInput{
			Limit: ptr(10),
		}
		resp, body := env.PostJSON("/api/auth/admin/list-users", listInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("ListUsers failed: status %d, body: %s", resp.StatusCode, body)
		}
		var listResp admindtos.AdminListUsersResponse
		if err := json.Unmarshal([]byte(body), &listResp); err != nil {
			t.Fatalf("Failed to decode ListUsers response: %v, raw: %s", err, body)
		}
		if len(listResp.Users) < 2 {
			t.Fatalf("Expected at least 2 users (admin + managed user), got %d", len(listResp.Users))
		}
	})

	t.Run("03 Set User Role", func(t *testing.T) {
		setRoleInput := admindtos.AdminSetUserRoleInput{
			UserID: managedUserID,
			Role:   enums.Admin,
		}
		resp, body := env.PostJSON("/api/auth/admin/set-user-role", setRoleInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("SetUserRole failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("04 Set User Password", func(t *testing.T) {
		setPwdInput := admindtos.AdminSetUserPasswordInput{
			UserID:      managedUserID,
			NewPassword: "AdminAssignedPassword789!",
		}
		resp, body := env.PostJSON("/api/auth/admin/set-user-password", setPwdInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("SetUserPassword failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("Ban User", func(t *testing.T) {
		banInput := admindtos.AdminBanUserInput{
			UserID:    managedUserID,
			BanReason: ptr("Policy violation"),
		}
		resp, body := env.PostJSON("/api/auth/admin/ban-user", banInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("BanUser failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("Unban User", func(t *testing.T) {
		unbanInput := admindtos.AdminUnbanUserInput{
			UserID: managedUserID,
		}
		resp, body := env.PostJSON("/api/auth/admin/unban-user", unbanInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("UnbanUser failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("List User Sessions", func(t *testing.T) {
		userSessionID = ulid.Make().String()
		_, err := env.Auth.IAuthServices.CreateSession(context.Background(), userSessionID, string(enums.User), managedUserID, nil)
		if err != nil {
			t.Fatalf("Failed to create session for managed user: %v", err)
		}

		listSessionsInput := admindtos.AdminListUserSessionsInput{
			UserID: managedUserID,
		}
		resp, body := env.PostJSON("/api/auth/admin/list-user-sessions", listSessionsInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("ListUserSessions failed: status %d, body: %s", resp.StatusCode, body)
		}
		var listSessionsResp admindtos.AdminListUserSessionsResponse
		if err := json.Unmarshal([]byte(body), &listSessionsResp); err != nil {
			t.Fatalf("Failed to decode ListUserSessions: %v, raw: %s", err, body)
		}
		if len(listSessionsResp.Sessions) == 0 {
			t.Fatalf("Expected at least 1 session for managed user, got 0")
		}
	})

	t.Run("Revoke Single User Session", func(t *testing.T) {
		revokeSingleInput := admindtos.AdminRevokeUserSessionInput{
			SessionToken: ptr(userSessionID),
		}
		resp, body := env.PostJSON("/api/auth/admin/revoke-user-session", revokeSingleInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("RevokeUserSession failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("Revoke All User Sessions", func(t *testing.T) {
		bulkSessionID := ulid.Make().String()
		_, _ = env.Auth.IAuthServices.CreateSession(context.Background(), bulkSessionID, string(enums.User), managedUserID, nil)

		revokeAllInput := admindtos.AdminRevokeUserSessionsInput{
			UserID: managedUserID,
		}
		resp, body := env.PostJSON("/api/auth/admin/revoke-user-sessions", revokeAllInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("RevokeUserSessions failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("Impersonate User", func(t *testing.T) {
		impersonateInput := admindtos.AdminImpersonateUserInput{
			UserID: managedUserID,
		}
		resp, body := env.PostJSON("/api/auth/admin/impersonate-user", impersonateInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("ImpersonateUser failed: status %d, body: %s", resp.StatusCode, body)
		}
		var impersonateResp dtos.SessionResponse
		if err := json.Unmarshal([]byte(body), &impersonateResp); err != nil || impersonateResp.Session == nil {
			t.Fatalf("Failed to decode ImpersonateUser response: %v, raw: %s", err, body)
		}
		impersonatedToken = impersonateResp.Session.Token
		if impersonatedToken == "" {
			t.Fatalf("Expected non-empty impersonated session token")
		}
	})

	t.Run("Stop Impersonating", func(t *testing.T) {
		impersonatedAuthHeader := map[string]string{"Authorization": "Bearer " + impersonatedToken}
		stopInput := admindtos.AdminStopImpersonatingInput{}
		resp, body := env.PostJSON("/api/auth/admin/stop-impersonating", stopInput, impersonatedAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("StopImpersonating failed: status %d, body: %s", resp.StatusCode, body)
		}
	})

	t.Run("Remove User", func(t *testing.T) {
		removeInput := admindtos.AdminRemoveUserInput{
			UserID: managedUserID,
		}
		resp, body := env.PostJSON("/api/auth/admin/remove-user", removeInput, adminAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("RemoveUser failed: status %d, body: %s", resp.StatusCode, body)
		}
	})
}
