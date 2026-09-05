package admin_test

import (
	"context"
	"testing"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models/enums"
	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/oklog/ulid/v2"
)

// TestAdminHandler_FullFlow invokes the Admin handlers directly in-process
// without HTTP networking, enabling direct line-by-line debugging of handlers and services.
func TestAdminHandler_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ctx := context.Background()
	_, adminAuthHeader := setupAdminUser(t, env)
	authHeaders := humatypes.AuthHeaders{Authorization: adminAuthHeader["Authorization"]}

	var managedUserID string
	var userSessionID string
	var impersonatedToken string

	t.Run("01 Create User", func(t *testing.T) {
		createInput := admindtos.AdminCreateUserInput{
			Email:    "handler_managed_user@example.com",
			Password: "InitialPassword123!",
			Name:     "Handler Managed User",
			Role:     enums.User,
		}
		resp, err := env.AdminHandler.CreateUser(ctx, &humaadmin.CreateUserInput{
			AuthHeaders: authHeaders,
			Body:        createInput,
		})
		if err != nil {
			t.Fatalf("CreateUser handler failed: %v", err)
		}
		if resp == nil || resp.Body.User == nil {
			t.Fatalf("Expected created user, got nil")
		}
		managedUserID = resp.Body.User.ID
		if managedUserID == "" {
			t.Fatalf("Expected non-empty managed user ID")
		}
	})

	t.Run("02 List Users", func(t *testing.T) {
		listInput := admindtos.AdminListUsersInput{
			Limit: ptr(10),
		}
		resp, err := env.AdminHandler.ListUsers(ctx, &humaadmin.ListUsersInput{
			AuthHeaders: authHeaders,
			Body:        listInput,
		})
		if err != nil {
			t.Fatalf("ListUsers handler failed: %v", err)
		}
		if resp == nil || len(resp.Body.Users) < 2 {
			t.Fatalf("Expected at least 2 users, got %v", resp)
		}
	})

	t.Run("03 Set User Role", func(t *testing.T) {
		setRoleInput := admindtos.AdminSetUserRoleInput{
			UserID: managedUserID,
			Role:   enums.Admin,
		}
		resp, err := env.AdminHandler.SetUserRole(ctx, &humaadmin.SetUserRoleInput{
			AuthHeaders: authHeaders,
			Body:        setRoleInput,
		})
		if err != nil {
			t.Fatalf("SetUserRole handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}
	})

	t.Run("04 Set User Password", func(t *testing.T) {
		setPwdInput := admindtos.AdminSetUserPasswordInput{
			UserID:      managedUserID,
			NewPassword: "AdminAssignedPassword789!",
		}
		resp, err := env.AdminHandler.SetUserPassword(ctx, &humaadmin.SetUserPasswordInput{
			AuthHeaders: authHeaders,
			Body:        setPwdInput,
		})
		if err != nil {
			t.Fatalf("SetUserPassword handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}
	})

	t.Run("05 Ban User", func(t *testing.T) {
		banInput := admindtos.AdminBanUserInput{
			UserID:    managedUserID,
			BanReason: ptr("Policy violation"),
		}
		resp, err := env.AdminHandler.BanUser(ctx, &humaadmin.BanUserInput{
			AuthHeaders: authHeaders,
			Body:        banInput,
		})
		if err != nil {
			t.Fatalf("BanUser handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}
	})

	t.Run("06 Unban User", func(t *testing.T) {
		unbanInput := admindtos.AdminUnbanUserInput{
			UserID: managedUserID,
		}
		resp, err := env.AdminHandler.UnbanUser(ctx, &humaadmin.UnbanUserInput{
			AuthHeaders: authHeaders,
			Body:        unbanInput,
		})
		if err != nil {
			t.Fatalf("UnbanUser handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}
	})

	t.Run("07 List User Sessions", func(t *testing.T) {
		userSessionID = ulid.Make().String()
		_, err := env.Auth.IAuthServices.CreateSession(ctx, userSessionID, string(enums.User), managedUserID, nil)
		if err != nil {
			t.Fatalf("Failed to create session for managed user: %v", err)
		}

		listSessionsInput := admindtos.AdminListUserSessionsInput{
			UserID: managedUserID,
		}
		resp, err := env.AdminHandler.ListUserSessions(ctx, &humaadmin.ListUserSessionsInput{
			AuthHeaders: authHeaders,
			Body:        listSessionsInput,
		})
		if err != nil {
			t.Fatalf("ListUserSessions handler failed: %v", err)
		}
		if resp == nil || len(resp.Body.Sessions) == 0 {
			t.Fatalf("Expected at least 1 session, got %v", resp)
		}
	})

	t.Run("08 Revoke Single User Session", func(t *testing.T) {
		revokeSingleInput := admindtos.AdminRevokeUserSessionInput{
			SessionToken: ptr(userSessionID),
		}
		resp, err := env.AdminHandler.RevokeUserSession(ctx, &humaadmin.RevokeUserSessionInput{
			AuthHeaders: authHeaders,
			Body:        revokeSingleInput,
		})
		if err != nil {
			t.Fatalf("RevokeUserSession handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}
	})

	t.Run("09 Revoke All User Sessions", func(t *testing.T) {
		bulkSessionID := ulid.Make().String()
		_, _ = env.Auth.IAuthServices.CreateSession(ctx, bulkSessionID, string(enums.User), managedUserID, nil)

		revokeAllInput := admindtos.AdminRevokeUserSessionsInput{
			UserID: managedUserID,
		}
		resp, err := env.AdminHandler.RevokeUserSessions(ctx, &humaadmin.RevokeUserSessionsInput{
			AuthHeaders: authHeaders,
			Body:        revokeAllInput,
		})
		if err != nil {
			t.Fatalf("RevokeUserSessions handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}
	})

	t.Run("10 Impersonate User", func(t *testing.T) {
		impersonateInput := admindtos.AdminImpersonateUserInput{
			UserID: managedUserID,
		}
		resp, err := env.AdminHandler.ImpersonateUser(ctx, &humaadmin.ImpersonateUserInput{
			AuthHeaders: authHeaders,
			Body:        impersonateInput,
		})
		if err != nil {
			t.Fatalf("ImpersonateUser handler failed: %v", err)
		}
		if resp == nil || resp.Body.Session == nil {
			t.Fatalf("Expected impersonated session, got nil")
		}
		impersonatedToken = resp.Body.Session.Token
		if impersonatedToken == "" {
			t.Fatalf("Expected non-empty impersonated session token")
		}
	})

	t.Run("11 Stop Impersonating", func(t *testing.T) {
		stopInput := admindtos.AdminStopImpersonatingInput{}
		resp, err := env.AdminHandler.StopImpersonating(ctx, &humaadmin.StopImpersonatingInput{
			AuthHeaders: humatypes.AuthHeaders{Authorization: "Bearer " + impersonatedToken},
			Body:        stopInput,
		})
		if err != nil {
			t.Fatalf("StopImpersonating handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}
	})

	t.Run("12 Remove User", func(t *testing.T) {
		removeInput := admindtos.AdminRemoveUserInput{
			UserID: managedUserID,
		}
		resp, err := env.AdminHandler.RemoveUser(ctx, &humaadmin.RemoveUserInput{
			AuthHeaders: authHeaders,
			Body:        removeInput,
		})
		if err != nil {
			t.Fatalf("RemoveUser handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Status {
			t.Fatalf("Expected status true, got %+v", resp)
		}
	})
}
