package gormadmin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	autherr "github.com/better-go-auth/goauth/src/common/error"
	"gorm.io/gorm"
)

// ListUserSessions returns all active, non-expired sessions for a user.
func (r *AdminRepo) ListUserSessions(ctx context.Context, userID string) ([]models.Session, error) {
	db := getDB(ctx, r.db)
	var sessions []models.Session
	err := db.Where("user_id = ? AND expires_at > ? AND revoked_at IS NULL", userID, time.Now().UTC()).
		Order("created_at desc").
		Find(&sessions).Error
	if err != nil {
		return nil, fmt.Errorf("gorm/admin: list user sessions: %w", err)
	}
	return sessions, nil
}

// RevokeUserSession deletes a single session by its ID or token.
func (r *AdminRepo) RevokeUserSession(ctx context.Context, sessionID, sessionToken string) error {
	db := getDB(ctx, r.db)
	q := db.Model(&models.Session{})
	if sessionID != "" {
		q = q.Where("id = ?", sessionID)
	} else if sessionToken != "" {
		q = q.Where("session_id = ?", sessionToken)
	} else {
		return autherr.New(autherr.BadRequest, "sessionToken or id is required", 400)
	}
	return q.Delete(&models.Session{}).Error
}

// RevokeUserSessions deletes all sessions belonging to a specific user.
func (r *AdminRepo) RevokeUserSessions(ctx context.Context, userID string) error {
	db := getDB(ctx, r.db)
	return db.Where("user_id = ?", userID).Delete(&models.Session{}).Error
}

// CreateImpersonationSession creates an impersonation session with impersonatedBy set.
func (r *AdminRepo) CreateImpersonationSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	db := getDB(ctx, r.db)
	if session.ID == "" {
		session.ID = models.NewID()
	}
	if err := db.Create(session).Error; err != nil {
		return nil, fmt.Errorf("gorm/admin: create impersonation session: %w", err)
	}
	return session, nil
}

// GetSessionByToken retrieves a session by its token.
func (r *AdminRepo) GetSessionByToken(ctx context.Context, token string) (*models.Session, error) {
	db := getDB(ctx, r.db)
	var session models.Session
	err := db.Preload("User").Where("session_id = ?", token).Take(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrSessionNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get session by token: %w", err)
	}
	return &session, nil
}

// DeleteSessionByID deletes a session by ID.
func (r *AdminRepo) DeleteSessionByID(ctx context.Context, id string) error {
	db := getDB(ctx, r.db)
	return db.Where("id = ?", id).Delete(&models.Session{}).Error
}
