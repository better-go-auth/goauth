package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/error"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	"github.com/birukbelay/gocmn/src/provider/db"
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
