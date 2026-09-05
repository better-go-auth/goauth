package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/app/core/core_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/error"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/birukbelay/gocmn/src/provider/db"

	// repoimpl "github.com/better-go-auth/better-go-auth/core/repository/interfaces"
	// authsvc "github.com/better-go-auth/better-go-auth/core/services/auth"
	// svcinterfaces "github.com/better-go-auth/better-go-auth/core/services/interfaces"

	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	adminmodels "github.com/better-go-auth/goauth/src/plugins/admin/models"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"golang.org/x/crypto/bcrypt"
)

var emailRegex = regexp.MustCompile(`^[A-Za-z0-9_'+\-.]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$`)

// AdminService implements IAdminService.
type AdminService struct {
	adminRepo repository.IAdminRepo
	// userRepo    repoimpl.IUserRepo
	// sessionRepo core_interfaces.S
	authConfig       config.GoAuthOptions
	adminConfig      adminmodels.AdminConfig
	secondaryStorage db.KeyValServ
	sessionServ      core_interfaces.ISessionService
	
}

var _ IAdminService = (*AdminService)(nil)

// NewAdminService creates a new AdminService.
func NewAdminService(
	adminRepo repository.IAdminRepo,
	// userRepo repoimpl.IUserRepo,
	// sessionRepo repoimpl.ISessionRepo,
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
		Base: models.Base{ID: models.NewID(), UpdatedAt: &now,},

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

// ImpersonateUser creates a new session acting as the target user.
func (s *AdminService) ImpersonateUser(ctx context.Context, input admindtos.AdminImpersonateUserInput, adminUser *dtos.UserResponse, reqMeta dtos.RequestMeta) (*dtos.SignInResponse, error) {
	if input.UserID == "" {
		return nil, autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}

	targetUser, err := s.adminRepo.GetUserByID(ctx, input.UserID)
	if err != nil {
		return nil, autherr.ErrUserNotFound
	}
	if targetUser.Banned {
		return nil, autherr.ErrUserBanned
	}

	rawToken, err := generateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("adminsvc: generate session token: %w", err)
	}

	expiresIn := s.adminConfig.ImpersonationSessionExpiresIn
	if expiresIn <= 0 {
		expiresIn = time.Duration(s.authConfig.SessionConfig.RefreshExpireMin)
	}
	if expiresIn <= 0 {
		expiresIn = 7 * 24 * time.Hour
	}
	expiresAt := time.Now().UTC().Add(expiresIn)

	session := &models.Session{
		Base:           models.Base{ID: models.NewID()},
		UserID:         targetUser.ID,
		SessionId:      rawToken,
		ExpiresAt:      expiresAt,
		ImpersonatedBy: &adminUser.ID,
		IPAddress:      &reqMeta.IPAddress,
		UserAgent:      &reqMeta.UserAgent,
		DeviceId:       reqMeta.DeviceID,
		DeviceName:     reqMeta.DeviceName,
		DeviceType:     reqMeta.DeviceType,
	}

	createdSession, err := s.adminRepo.CreateImpersonationSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("adminsvc: create impersonation session: %w", err)
	}

	sessData := dtos.SessionToData(createdSession)
	userResp := dtos.UserToResponse(targetUser)

	// Save to secondary storage if enabled
	if store := s.secondaryStorage; store != nil {
		sessResp := &dtos.SessionResponse{
			Session: sessData,
			User:    userResp,
		}
		payloadBytes, _ := json.Marshal(map[string]interface{}{
			"session": sessData,
			"user":    userResp,
		})
		_ = store.Set(ctx, rawToken, string(payloadBytes), expiresIn)
		_ = sessResp
	}

	return &dtos.SignInResponse{
		User:        userResp,
		Token:       rawToken,
		SessionData: sessData,
	}, nil
}

// StopImpersonating terminates the current impersonation session.
func (s *AdminService) StopImpersonating(ctx context.Context, currentSessionToken string) error {
	if currentSessionToken == "" {
		return autherr.New(autherr.BadRequest, "No active session token provided", http.StatusBadRequest)
	}

	session, err := s.adminRepo.GetSessionByToken(ctx, currentSessionToken)
	if err != nil {
		return autherr.ErrSessionNotFound
	}

	if session.ImpersonatedBy == nil || *session.ImpersonatedBy == "" {
		return autherr.New(autherr.BadRequest, "Not currently impersonating a user", http.StatusBadRequest)
	}

	// Delete the impersonation session
	if err := s.adminRepo.DeleteSessionByID(ctx, session.ID); err != nil {
		return fmt.Errorf("adminsvc: delete impersonation session: %w", err)
	}

	if store := s.secondaryStorage; store != nil {
		_ = store.Delete(ctx, currentSessionToken)
	}

	return nil
}

// ListUserSessions returns all active sessions for a target user.
func (s *AdminService) ListUserSessions(ctx context.Context, input admindtos.AdminListUserSessionsInput, _ string) ([]dtos.SessionData, error) {
	if input.UserID == "" {
		return nil, autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}

	sessions, err := s.adminRepo.ListUserSessions(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	data := make([]dtos.SessionData, 0, len(sessions))
	for i := range sessions {
		data = append(data, *dtos.SessionToData(&sessions[i]))
	}
	return data, nil
}

// RevokeUserSession invalidates a specific session for a user.
func (s *AdminService) RevokeUserSession(ctx context.Context, input admindtos.AdminRevokeUserSessionInput, _ string) error {
	var token, id string
	if input.SessionToken != nil {
		token = *input.SessionToken
	}
	if input.ID != nil {
		id = *input.ID
	}
	if token == "" && id == "" {
		return autherr.New(autherr.BadRequest, "sessionToken or id is required", http.StatusBadRequest)
	}

	if err := s.adminRepo.RevokeUserSession(ctx, id, token); err != nil {
		return fmt.Errorf("adminsvc: revoke session: %w", err)
	}

	if store := s.secondaryStorage; store != nil && token != "" {
		_ = store.Delete(ctx, token)
	}

	return nil
}

// RevokeUserSessions invalidates all active sessions for a target user.
func (s *AdminService) RevokeUserSessions(ctx context.Context, input admindtos.AdminRevokeUserSessionsInput, _ string) error {
	if input.UserID == "" {
		return autherr.New(autherr.BadRequest, "userId is required", http.StatusBadRequest)
	}

	// deleteSecondaryStorageSessions(s.secondaryStorage, input.UserID)
	if err := s.sessionServ.DeleteAllUserSessions(ctx, input.UserID); err != nil {
		return fmt.Errorf("adminsvc: revoke user sessions: %w", err)
	}
	return nil
}

func generateRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type activeSessionEntry struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

func deleteSecondaryStorageSessions(store db.KeyValServ, userID string) {
	if store == nil {
		return
	}
	key := "active-sessions-" + userID
	var list []activeSessionEntry

	if raw, _, err := store.Get(context.Background(), key); err == nil && raw != nil {
		if strVal, ok := raw.(string); ok {
			_ = json.Unmarshal([]byte(strVal), &list)
		}
	}

	for _, entry := range list {
		_ = store.Delete(context.Background(), entry.Token)
	}
	_ = store.Delete(context.Background(), key)
}
