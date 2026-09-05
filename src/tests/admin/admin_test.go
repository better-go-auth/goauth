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
	tokens, err := env.Auth.AuthServices.CreateSession(context.Background(), sessionID, string(enums.Admin), adminUser.ID, nil)
	if err != nil {
		t.Fatalf("Failed to create admin session: %v", err)
	}

	return adminUser.ID, map[string]string{"Authorization": "Bearer " + tokens.AccessToken}
}

func TestAdminE2E_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t)
	_, adminAuthHeader := setupAdminUser(t, env)

	// 1. CreateUser (Admin creates a normal user directly)
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
	managedUserID := createResp.User.ID
	if managedUserID == "" {
		t.Fatalf("Expected non-empty managed user ID")
	}

	// 2. ListUsers
	listInput := admindtos.AdminListUsersInput{
		Limit: ptr(10),
	}
	resp, body = env.PostJSON("/api/auth/admin/list-users", listInput, adminAuthHeader)
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

	// 3. SetUserRole
	setRoleInput := admindtos.AdminSetUserRoleInput{
		UserID: managedUserID,
		Role:   enums.Admin,
	}
	resp, body = env.PostJSON("/api/auth/admin/set-user-role", setRoleInput, adminAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("SetUserRole failed: status %d, body: %s", resp.StatusCode, body)
	}

	// 4. SetUserPassword
	setPwdInput := admindtos.AdminSetUserPasswordInput{
		UserID:      managedUserID,
		NewPassword: "AdminAssignedPassword789!",
	}
	resp, body = env.PostJSON("/api/auth/admin/set-user-password", setPwdInput, adminAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("SetUserPassword failed: status %d, body: %s", resp.StatusCode, body)
	}

	// 5. BanUser
	banInput := admindtos.AdminBanUserInput{
		UserID:    managedUserID,
		BanReason: ptr("Policy violation"),
	}
	resp, body = env.PostJSON("/api/auth/admin/ban-user", banInput, adminAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("BanUser failed: status %d, body: %s", resp.StatusCode, body)
	}

	// 6. UnbanUser
	unbanInput := admindtos.AdminUnbanUserInput{
		UserID: managedUserID,
	}
	resp, body = env.PostJSON("/api/auth/admin/unban-user", unbanInput, adminAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("UnbanUser failed: status %d, body: %s", resp.StatusCode, body)
	}

	// Create an active session for the managed user to test session controls
	userSessionID := ulid.Make().String()
	userTokens, err := env.Auth.AuthServices.CreateSession(context.Background(), userSessionID, string(enums.User), managedUserID, nil)
	if err != nil {
		t.Fatalf("Failed to create session for managed user: %v", err)
	}

	// 7. ListUserSessions
	listSessionsInput := admindtos.AdminListUserSessionsInput{
		UserID: managedUserID,
	}
	resp, body = env.PostJSON("/api/auth/admin/list-user-sessions", listSessionsInput, adminAuthHeader)
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

	// 8. RevokeUserSession
	revokeSingleInput := admindtos.AdminRevokeUserSessionInput{
		SessionToken: ptr(userSessionID),
	}
	resp, body = env.PostJSON("/api/auth/admin/revoke-user-session", revokeSingleInput, adminAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("RevokeUserSession failed: status %d, body: %s", resp.StatusCode, body)
	}

	// Create another session to test RevokeUserSessions (bulk)
	bulkSessionID := ulid.Make().String()
	_, _ = env.Auth.AuthServices.CreateSession(context.Background(), bulkSessionID, string(enums.User), managedUserID, nil)

	// 9. RevokeUserSessions
	revokeAllInput := admindtos.AdminRevokeUserSessionsInput{
		UserID: managedUserID,
	}
	resp, body = env.PostJSON("/api/auth/admin/revoke-user-sessions", revokeAllInput, adminAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("RevokeUserSessions failed: status %d, body: %s", resp.StatusCode, body)
	}

	// 10. ImpersonateUser
	impersonateInput := admindtos.AdminImpersonateUserInput{
		UserID: managedUserID,
	}
	resp, body = env.PostJSON("/api/auth/admin/impersonate-user", impersonateInput, adminAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("ImpersonateUser failed: status %d, body: %s", resp.StatusCode, body)
	}
	var impersonateResp dtos.SessionResponse
	if err := json.Unmarshal([]byte(body), &impersonateResp); err != nil || impersonateResp.Session == nil {
		t.Fatalf("Failed to decode ImpersonateUser response: %v, raw: %s", err, body)
	}
	impersonatedToken := impersonateResp.Session.Token
	if impersonatedToken == "" {
		t.Fatalf("Expected non-empty impersonated session token")
	}

	// 11. StopImpersonating
	impersonatedAuthHeader := map[string]string{"Authorization": "Bearer " + impersonatedToken}
	stopInput := admindtos.AdminStopImpersonatingInput{}
	resp, body = env.PostJSON("/api/auth/admin/stop-impersonating", stopInput, impersonatedAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("StopImpersonating failed: status %d, body: %s", resp.StatusCode, body)
	}

	// 12. RemoveUser
	removeInput := admindtos.AdminRemoveUserInput{
		UserID: managedUserID,
	}
	resp, body = env.PostJSON("/api/auth/admin/remove-user", removeInput, adminAuthHeader)
	if !isSuccess(resp.StatusCode) {
		t.Fatalf("RemoveUser failed: status %d, body: %s", resp.StatusCode, body)
	}

	_ = userTokens
}
