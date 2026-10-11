package services

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"

	// corerepo "github.com/better-go-auth/goauth/core/repository/interfaces"
	// authsvc "github.com/better-go-auth/goauth/core/services/auth"
	// svcinterfaces "github.com/better-go-auth/goauth/core/services/interfaces"

	adminmodels "github.com/better-go-auth/goauth/src/plugins/admin/config"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

var emailRegex = regexp.MustCompile(`^[A-Za-z0-9_'+\-.]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$`)

// AdminService implements IAdminService.
type AdminService struct {
	adminRepo repository.IAdminRepo
	// userRepo    corerepo.IUserRepo
	// sessionRepo core_interfaces.S
	authConfig       config.AuthConfig
	adminConfig      adminmodels.AdminConfig
	secondaryStorage sec_storage.SecondaryStorage
	sessionMgr       serv_interfaces.ISessionManager
	// legacy_sessionServ serv_interfaces.LegacySessionService
	hooks plugins.HookRegistry
}

var _ IAdminService = (*AdminService)(nil)

// SetHooks configures the lifecycle hooks for the admin service.
func (s *AdminService) SetHooks(hooks plugins.HookRegistry) {
	s.hooks = hooks
}

// SetSessionService configures the normal session service used to create and revoke sessions.
func (s *AdminService) SetSessionService(sessionServ serv_interfaces.ISessionManager) {
	s.sessionMgr = sessionServ
}

// SetAuthConfig provides the core auth configuration.
func (s *AdminService) SetAuthConfig(conf config.AuthConfig) {
	s.authConfig = conf
}

// NewAdminService creates a new AdminService.
func NewAdminService(
	adminRepo repository.IAdminRepo,
	// userRepo corerepo.IUserRepo,
	// sessionRepo corerepo.ISessionRepo,
	// authConfig config.AuthConfig,
	adminConfig adminmodels.AdminConfig,
) *AdminService {
	return &AdminService{
		adminRepo: adminRepo,
		// userRepo:    userRepo,
		// sessionRepo: sessionRepo,
		// authConfig:  authConfig,
		adminConfig: adminConfig,
	}
}

// ListUsers searches, filters, and paginates users.
func (s *AdminService) ListUsers(ctx context.Context, input admindtos.AdminListUsersInput, _ string) (*admindtos.AdminListUsersResponse, error) {
	users, total, err := s.adminRepo.ListUsers(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("adminsvc: list users: %w", err)
	}
	return &admindtos.AdminListUsersResponse{
		Users: dtos.UsersToResponse(users),
		Total: total,
	}, nil
}

// CreateUser creates a new user account with role directly.
func (s *AdminService) CreateUser(ctx context.Context, input admindtos.AdminCreateUserInput, _ string) (*dtos.UserResponse, error) {
	email := strings.TrimSpace(strings.ToLower(input.Email))
	if email == "" || !emailRegex.MatchString(email) {
		return nil, autherr.ErrInvalidEmail
	}

	if len(input.Password) < 8 {
		return nil, autherr.ErrPasswordTooShort
	}
	if len(input.Password) > 128 {
		return nil, autherr.ErrPasswordTooLong
	}

	// Check if user exists
	if existing, _ := s.adminRepo.GetUserByEmail(ctx, email); existing != nil {
		return nil, autherr.ErrEmailExists
	}

	role := s.adminConfig.DefaultRole
	if input.Role != "" {
		role = input.Role
	}

	hash, err := authcrypto.NewPasswords(s.authConfig).Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("adminsvc: hash password: %w", err)
	}

	now := time.Now().UTC()
	user := &models.User{
		UserDto: models.UserDto{
			FirstName:     input.Name,
			Email:         email,
			EmailVerified: true,
			Role:          role,
		},
		Base: models.Base{ID: models.NewID(), UpdatedAt: now},
	}

	created, err := s.adminRepo.CreateUserWithAccount(ctx, user, hash)
	if err != nil {
		return nil, fmt.Errorf("adminsvc: create user: %w", err)
	}

	u := dtos.UserFromModel(created)
	return &u, nil
}

// SetUserRole assigns a new role to a user.
func (s *AdminService) SetUserRole(ctx context.Context, input admindtos.AdminSetUserRoleInput, _ string) (*dtos.UserResponse, error) {
	if input.UserID == "" {
		return nil, autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}
	if input.Role == "" {
		return nil, autherr.New(autherr.BadRequest, "role is required", http.StatusBadRequest)
	}

	user, err := s.adminRepo.SetUserRole(ctx, input.UserID, input.Role)
	if err != nil {
		return nil, err
	}

	// Refresh sessions
	if s.sessionMgr != nil {
		if err := s.sessionMgr.DeleteUserSessions(ctx, input.UserID); err != nil {
			return nil, err
		}
	} else {
		_ = s.adminRepo.RevokeUserSessions(ctx, input.UserID)
	}

	u := dtos.UserFromModel(user)
	return &u, nil
}

// SetUserPassword overrides a user's password directly.
func (s *AdminService) SetUserPassword(ctx context.Context, input admindtos.AdminSetUserPasswordInput, _ string) error {
	if input.UserID == "" {
		return autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}
	if len(input.NewPassword) < 8 {
		return autherr.ErrPasswordTooShort
	}
	if len(input.NewPassword) > 128 {
		return autherr.ErrPasswordTooLong
	}

	// Verify user exists
	if _, err := s.adminRepo.GetUserByID(ctx, input.UserID); err != nil {
		return autherr.ErrUserNotFound
	}

	hash, err := authcrypto.NewPasswords(s.authConfig).Hash(input.NewPassword)
	if err != nil {
		return fmt.Errorf("adminsvc: hash password: %w", err)
	}

	if err := s.adminRepo.SetUserPassword(ctx, input.UserID, hash); err != nil {
		return fmt.Errorf("adminsvc: set user password: %w", err)
	}
	return nil
}

// RemoveUser deletes a user and all their sessions/accounts.
func (s *AdminService) RemoveUser(ctx context.Context, input admindtos.AdminRemoveUserInput, _ string) error {
	if input.UserID == "" {
		return autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}

	if s.sessionMgr != nil {
		if err := s.sessionMgr.DeleteUserSessions(ctx, input.UserID); err != nil {
			return fmt.Errorf("adminsvc: revoke user sessions: %w", err)
		}
	}
	if err := s.adminRepo.RemoveUser(ctx, input.UserID); err != nil {
		return fmt.Errorf("adminsvc: remove user: %w", err)
	}
	if s.hooks != nil {
		_ = s.hooks.TriggerUserDeleted(ctx, input.UserID)
	}
	return nil
}

// BanUser bans a user and terminates all active sessions.
func (s *AdminService) BanUser(ctx context.Context, input admindtos.AdminBanUserInput, _ string) (*dtos.UserResponse, error) {
	if input.UserID == "" {
		return nil, autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}

	var expiresAt *time.Time
	if input.BanExpiresIn != nil && *input.BanExpiresIn > 0 {
		exp := time.Now().UTC().Add(time.Duration(*input.BanExpiresIn) * time.Second)
		expiresAt = &exp
	}

	user, err := s.adminRepo.BanUser(ctx, input.UserID, input.BanReason, expiresAt)
	if err != nil {
		return nil, err
	}

	if s.hooks != nil {
		_ = s.hooks.TriggerUserBanned(ctx, input.UserID, input.BanReason)
	}

	// Terminate all sessions for the banned user
	deleteSecondaryStorageSessions(s.secondaryStorage, input.UserID)
	if s.sessionMgr != nil {
		if err := s.sessionMgr.DeleteUserSessions(ctx, input.UserID); err != nil {
			return nil, fmt.Errorf("adminsvc: revoke sessions on ban: %w", err)
		}
	} else {
		_ = s.adminRepo.RevokeUserSessions(ctx, input.UserID)
	}

	u := dtos.UserFromModel(user)
	return &u, nil
}

// UnbanUser removes an existing ban on a user.
func (s *AdminService) UnbanUser(ctx context.Context, input admindtos.AdminUnbanUserInput, _ string) (*dtos.UserResponse, error) {
	if input.UserID == "" {
		return nil, autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}

	user, err := s.adminRepo.UnbanUser(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	u := dtos.UserFromModel(user)
	return &u, nil
}

// GetUser retrieves a single user by ID.
func (s *AdminService) GetUser(ctx context.Context, userID string) (*dtos.UserResponse, error) {
	if userID == "" {
		return nil, autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}
	user, err := s.adminRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	u := dtos.UserFromModel(user)
	return &u, nil
}

// UpdateUser updates user fields by ID.
func (s *AdminService) UpdateUser(ctx context.Context, input admindtos.AdminUpdateUserInput) (*dtos.UserResponse, error) {
	if input.UserID == "" {
		return nil, autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}
	if len(input.Data) == 0 {
		return nil, autherr.New(autherr.BadRequest, "no data to update", http.StatusBadRequest)
	}
	// Password cannot be updated via update-user (Better Auth specification)
	if _, ok := input.Data["password"]; ok {
		return nil, autherr.New(autherr.BadRequest, "password cannot be updated via update-user", http.StatusBadRequest)
	}

	updated, err := s.adminRepo.UpdateUser(ctx, input.UserID, input.Data)
	if err != nil {
		return nil, err
	}
	u := dtos.UserFromModel(updated)
	return &u, nil
}

// HasPermission checks if the given user or role has the requested permissions.
func (s *AdminService) HasPermission(ctx context.Context, input admindtos.AdminHasPermissionInput, adminUser *dtos.UserResponse) (*admindtos.AdminHasPermissionResponse, error) {
	perms := input.Permissions
	if len(perms) == 0 && len(input.Permission) > 0 {
		perms = input.Permission
	}
	if len(perms) == 0 {
		return nil, autherr.New(autherr.BadRequest, "invalid permission check: no permission(s) were passed", http.StatusBadRequest)
	}

	targetRole := input.Role
	if targetRole == "" && input.UserID != "" {
		user, err := s.adminRepo.GetUserByID(ctx, input.UserID)
		if err != nil {
			return nil, err
		}
		targetRole = user.Role.S()
	}
	if targetRole == "" && adminUser != nil {
		targetRole = adminUser.Role
	}

	// Admin role has all permissions
	isAdmin := enums.HasRole(targetRole, enums.Admin.S()) || targetRole == "admin"
	if isAdmin {
		return &admindtos.AdminHasPermissionResponse{Success: true}, nil
	}

	return &admindtos.AdminHasPermissionResponse{Success: false}, nil
}
