package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

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

	deleteSecondaryStorageSessions(s.secondaryStorage, input.UserID)
	if s.sessionServ != nil {
		if err := s.sessionServ.DeleteAllUserSessions(ctx, input.UserID); err != nil {
			return fmt.Errorf("adminsvc: revoke user sessions: %w", err)
		}
	} else {
		if err := s.adminRepo.RevokeUserSessions(ctx, input.UserID); err != nil {
			return fmt.Errorf("adminsvc: revoke user sessions: %w", err)
		}
	}
	return nil
}

//====================================   IMPERSINATION ===========================
//
//===============================================================================

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
	if s.sessionServ == nil {
		return nil, fmt.Errorf("adminsvc: session service not configured")
	}

	expiresIn := s.adminConfig.ImpersonationSessionExpiresIn
	if expiresIn <= 0 {
		expiresIn = s.authConfig.GoAuth.Session.JWT.RefreshExpiresIn
	}

	// Issue a regular JWT session so the impersonated token passes the auth middleware.
	sessionID := models.NewSecureId()
	tokens, err := s.sessionServ.CreateSession(ctx, sessionID, targetUser.Role.S(), targetUser.ID, &models.SessionOpt{
		ImpersonatedBy: &adminUser.ID,
		ExpiresIn:      expiresIn,
	})
	if err != nil {
		return nil, fmt.Errorf("adminsvc: create impersonation session: %w", err)
	}

	createdSession, err := s.adminRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("adminsvc: load impersonation session: %w", err)
	}

	sessData := dtos.SessionToData(createdSession)
	// The refresh token is deliberately not returned: impersonation must not outlive its session row.
	sessData.Token = tokens.AccessToken
	userResp := dtos.UserToResponse(targetUser)

	return &dtos.SignInResponse{
		User:        userResp,
		Token:       tokens.AccessToken,
		SessionData: sessData,
	}, nil
}

// StopImpersonating terminates the impersonation session identified by sessionID.
func (s *AdminService) StopImpersonating(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return autherr.New(autherr.BadRequest, "No active session provided", http.StatusBadRequest)
	}

	session, err := s.adminRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return autherr.ErrSessionNotFound
	}

	if session.ImpersonatedBy == nil || *session.ImpersonatedBy == "" {
		return autherr.New(autherr.BadRequest, "Not currently impersonating a user", http.StatusBadRequest)
	}

	if s.sessionServ != nil {
		// also blacklists the session so the impersonation access token stops working
		if err := s.sessionServ.DeleteSession(ctx, session.ID); err != nil {
			return fmt.Errorf("adminsvc: delete impersonation session: %w", err)
		}
		return nil
	}
	if err := s.adminRepo.DeleteSessionByID(ctx, session.ID); err != nil {
		return fmt.Errorf("adminsvc: delete impersonation session: %w", err)
	}
	return nil
}

type activeSessionEntry struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

func deleteSecondaryStorageSessions(store sec_storage.SecondaryStorage, userID string) {
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
