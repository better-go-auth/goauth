package gormauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	loc_errors "github.com/better-go-auth/goauth/src/common/error"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SessionRepo implements repo_interfaces.ISessionRepo using GORM.
type SessionRepo struct {
	db *gorm.DB
}

var _ repo_interfaces.ISessionRepo = (*SessionRepo)(nil)

// NewSessionRepo creates a new GORM-backed SessionRepo.
func NewSessionRepo(db *gorm.DB) repo_interfaces.ISessionRepo {
	return &SessionRepo{db: db}
}

func (r *SessionRepo) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if session.ID == "" {
		session.ID = models.NewID()
	}
	if err := gormutil.GetDB(ctx, r.db).Create(session).Error; err != nil {
		return nil, fmt.Errorf("gorm/session: create: %w", err)
	}
	return session, nil
}

func (r *SessionRepo) UpsertSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if session.ID == "" {
		session.ID = models.NewID()
	}
	err := gormutil.GetDB(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "session_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"hashed_token", "device_token", "active_org_id", "expires_at"}),
	}).Create(session).Error
	if err != nil {
		return nil, fmt.Errorf("gorm/session: upsert: %w", err)
	}
	return session, nil
}

func (r *SessionRepo) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	var session models.Session
	err := gormutil.GetDB(ctx, r.db).Where("id = ? OR session_id = ?", id, id).Take(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/session: not found")
		}
		return nil, fmt.Errorf("gorm/session: get by id: %w", err)
	}
	return &session, nil
}

func (r *SessionRepo) GetSessionBySessionID(ctx context.Context, sessionID string) (*models.Session, error) {
	var session models.Session
	err := gormutil.GetDB(ctx, r.db).Where("session_id = ?", sessionID).Take(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/session: not found")
		}
		return nil, fmt.Errorf("gorm/session: get by session id: %w", err)
	}
	return &session, nil
}

func (r *SessionRepo) GetSessionByToken(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	err := gormutil.GetDB(ctx, r.db).Where("session_id = ? OR hashed_token = ?", token, token).Take(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/session: not found")
		}
		return nil, fmt.Errorf("gorm/session: get by token: %w", err)
	}
	return &session, nil
}

func (r *SessionRepo) UpdateSession(ctx context.Context, sessionID string, data map[string]interface{}) (*models.Session, error) {
	db := gormutil.GetDB(ctx, r.db)
	result := db.Model(&models.Session{}).Where("session_id = ? OR id = ?", sessionID, sessionID).Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/session: update: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, loc_errors.NotFoundErr("gorm/session: not found for update")
	}
	return r.GetSessionByID(ctx, sessionID)
}

func (r *SessionRepo) DeleteSession(ctx context.Context, sessionID string) error {
	result := gormutil.GetDB(ctx, r.db).Where("session_id = ? OR id = ?", sessionID, sessionID).Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("gorm/session: delete: %w", result.Error)
	}
	return nil
}

func (r *SessionRepo) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	result := gormutil.GetDB(ctx, r.db).Where("user_id = ?", userID).Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("gorm/session: delete by user: %w", result.Error)
	}
	return nil
}

func (r *SessionRepo) ListSessionsByUserID(ctx context.Context, userID string) ([]models.Session, error) {
	var sessions []models.Session
	err := gormutil.GetDB(ctx, r.db).Where("user_id = ?", userID).Find(&sessions).Error
	if err != nil {
		return nil, fmt.Errorf("gorm/session: list by user: %w", err)
	}
	return sessions, nil
}

func (r *SessionRepo) ListSessions(ctx context.Context, filter models.SessionFilter, pagi dtos.PaginationInput) ([]models.Session, int64, error) {
	var sessions []models.Session
	var total int64

	db := gormutil.GetDB(ctx, r.db).Model(&models.Session{})
	if filter.UserId != "" {
		db = db.Where("user_id = ?", filter.UserId)
	}
	if filter.SessionId != "" {
		db = db.Where("session_id = ?", filter.SessionId)
	}
	if filter.ID != "" {
		db = db.Where("id = ?", filter.ID)
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/session: count: %w", err)
	}

	limit := pagi.Limit
	if limit <= 0 {
		limit = 10
	}
	offset := pagi.Page
	if offset < 0 {
		offset = 0
	}

	err := db.Limit(limit).Offset(offset).Find(&sessions).Error
	if err != nil {
		return nil, 0, fmt.Errorf("gorm/session: list: %w", err)
	}
	return sessions, total, nil
}
