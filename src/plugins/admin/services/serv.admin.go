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
	"github.com/better-go-auth/goauth/src/plugins"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"

	// corerepo "github.com/better-go-auth/goauth/core/repository/interfaces"
	// authsvc "github.com/better-go-auth/goauth/core/services/auth"
	// svcinterfaces "github.com/better-go-auth/goauth/core/services/interfaces"

	adminmodels "github.com/better-go-auth/goauth/src/plugins/admin/config"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"golang.org/x/crypto/bcrypt"
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
	sessionServ      serv_interfaces.ISessionService
	hooks            plugins.HookRegistry
}

var _ IAdminService = (*AdminService)(nil)

// SetHooks configures the lifecycle hooks for the admin service.
func (s *AdminService) SetHooks(hooks plugins.HookRegistry) {
	s.hooks = hooks
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

	userResps := make([]dtos.UserResponse, 0, len(users))
	for i := range users {
		userResps = append(userResps, *dtos.UserToResponse(&users[i]))
	}

	return &admindtos.AdminListUsersResponse{
		Users: userResps,
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

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("adminsvc: hash password: %w", err)
	}

	now := time.Now().UTC()
	user := &models.User{
		UserDto: models.UserDto{
			FirstName:     input.Name,
			Email:         &email,
			EmailVerified: true,
			Role:          role,
		},
		Base: models.Base{ID: models.NewID(), UpdatedAt: &now},
	}

	created, err := s.adminRepo.CreateUserWithAccount(ctx, user, string(hash))
	if err != nil {
		return nil, fmt.Errorf("adminsvc: create user: %w", err)
	}

	return dtos.UserToResponse(created), nil
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
	if s.sessionServ != nil {
		if err := s.sessionServ.DeleteAllUserSessions(ctx, input.UserID); err != nil {
			return nil, err
		}
	} else {
		_ = s.adminRepo.RevokeUserSessions(ctx, input.UserID)
	}

	return dtos.UserToResponse(user), nil
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

	hash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("adminsvc: hash password: %w", err)
	}

	if err := s.adminRepo.SetUserPassword(ctx, input.UserID, string(hash)); err != nil {
		return fmt.Errorf("adminsvc: set user password: %w", err)
	}
	return nil
}

// RemoveUser deletes a user and all their sessions/accounts.
func (s *AdminService) RemoveUser(ctx context.Context, input admindtos.AdminRemoveUserInput, _ string) error {
	if input.UserID == "" {
		return autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}

	if s.sessionServ != nil {
		if err := s.sessionServ.DeleteAllUserSessions(ctx, input.UserID); err != nil {
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
	if s.sessionServ != nil {
		if err := s.sessionServ.DeleteAllUserSessions(ctx, input.UserID); err != nil {
			return nil, fmt.Errorf("adminsvc: revoke sessions on ban: %w", err)
		}
	} else {
		_ = s.adminRepo.RevokeUserSessions(ctx, input.UserID)
	}

	return dtos.UserToResponse(user), nil
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
	return dtos.UserToResponse(user), nil
}
