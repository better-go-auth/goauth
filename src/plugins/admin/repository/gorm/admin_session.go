package gormadmin

import (
	"context"
	"errors"
	"fmt"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ListUserSessions returns all active, non-expired sessions for a user.
func (r *AdminRepo) ListUserSessions(ctx context.Context, userID string) ([]models.Session, error) {
	db := getDB(ctx, r.db)
	s := &models.Session{}
	var sessions []models.Session
	err := db.Where(&models.Session{UserID: userID}, "UserID").
		Where(clause.Gt{Column: gormutil.Col(r.db, s, "ExpiresAt"), Value: time.Now().UTC()}).
		Order(gormutil.OrderBy(r.db, s, "CreatedAt", true)).
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
		q = q.Where(&models.Session{Base: models.Base{ID: sessionID}}, "ID")
	} else if sessionToken != "" {
		q = q.Where(&models.Session{Token: sessionToken}, "Token")
	} else {
		return autherr.New(autherr.BadRequest, "sessionToken or id is required", 400)
	}
	return q.Delete(&models.Session{}).Error
}

// RevokeUserSessions deletes all sessions belonging to a specific user.
func (r *AdminRepo) RevokeUserSessions(ctx context.Context, userID string) error {
	db := getDB(ctx, r.db)
	return db.Where(&models.Session{UserID: userID}, "UserID").Delete(&models.Session{}).Error
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

// GetSessionByID retrieves a session by its ID.
func (r *AdminRepo) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	db := getDB(ctx, r.db)
	var session models.Session
	err := db.Preload("User").Where(&models.Session{Base: models.Base{ID: id}}, "ID").Take(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, autherr.ErrSessionNotFound
		}
		return nil, fmt.Errorf("gorm/admin: get session by id: %w", err)
	}
	return &session, nil
}

// DeleteSessionByID deletes a session by ID.
func (r *AdminRepo) DeleteSessionByID(ctx context.Context, id string) error {
	db := getDB(ctx, r.db)
	return db.Where(&models.Session{Base: models.Base{ID: id}}, "ID").Delete(&models.Session{}).Error
}
