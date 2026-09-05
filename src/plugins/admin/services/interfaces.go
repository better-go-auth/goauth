package services

import (
	"context"

	"github.com/better-go-auth/goauth/src/models/dtos"
	// svcinterfaces "github.com/better-go-auth/better-go-auth/core/services/interfaces"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
)

// IAdminService defines the business logic operations for the Admin plugin.
type IAdminService interface {
	// ListUsers searches, filters, and paginates users (admin only).
	ListUsers(ctx context.Context, input admindtos.AdminListUsersInput, adminUserID string) (*admindtos.AdminListUsersResponse, error)

	// CreateUser creates a new user account with role directly without requiring email verification.
	CreateUser(ctx context.Context, input admindtos.AdminCreateUserInput, adminUserID string) (*dtos.UserResponse, error)

	// SetUserRole assigns a new platform role to a user.
	SetUserRole(ctx context.Context, input admindtos.AdminSetUserRoleInput, adminUserID string) (*dtos.UserResponse, error)

	// SetUserPassword overrides a user's password directly as an administrator.
	SetUserPassword(ctx context.Context, input admindtos.AdminSetUserPasswordInput, adminUserID string) error

	// RemoveUser deletes a user and all their associated records.
	RemoveUser(ctx context.Context, input admindtos.AdminRemoveUserInput, adminUserID string) error

	// BanUser bans a user permanently or temporarily, terminating active sessions.
	BanUser(ctx context.Context, input admindtos.AdminBanUserInput, adminUserID string) (*dtos.UserResponse, error)

	// UnbanUser removes an existing ban on a user.
	UnbanUser(ctx context.Context, input admindtos.AdminUnbanUserInput, adminUserID string) (*dtos.UserResponse, error)

	// ImpersonateUser creates a new session acting as the target user with impersonatedBy set.
	ImpersonateUser(ctx context.Context, input admindtos.AdminImpersonateUserInput, adminUser *dtos.UserResponse, reqMeta dtos.RequestMeta) (*dtos.SignInResponse, error)

	// StopImpersonating terminates the current impersonation session.
	StopImpersonating(ctx context.Context, currentSessionToken string) error

	// ListUserSessions returns all active sessions for a target user.
	ListUserSessions(ctx context.Context, input admindtos.AdminListUserSessionsInput, adminUserID string) ([]dtos.SessionData, error)

	// RevokeUserSession invalidates a specific session for a user.
	RevokeUserSession(ctx context.Context, input admindtos.AdminRevokeUserSessionInput, adminUserID string) error

	// RevokeUserSessions invalidates all active sessions for a target user.
	RevokeUserSessions(ctx context.Context, input admindtos.AdminRevokeUserSessionsInput, adminUserID string) error
}
