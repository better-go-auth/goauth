package gormauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	loc_errors "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
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
	s := &models.Session{}
	err := gormutil.GetDB(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{gormutil.Col(r.db, s, "ID")},
		DoUpdates: clause.AssignmentColumns(gormutil.ColNames(r.db, s, "Token", "DeviceToken", "ActiveOrganizationID", "ActiveOrganizationRole", "ExpiresAt")),
	}).Create(session).Error
	if err != nil {
		return nil, fmt.Errorf("gorm/session: upsert: %w", err)
	}
	return session, nil
}

func (r *SessionRepo) FindSessionByID(ctx context.Context, id string) (*models.Session, error) {
	var session models.Session
	err := gormutil.GetDB(ctx, r.db).Where(sessionByID(id), "ID").Take(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/session: not found")
		}
		return nil, fmt.Errorf("gorm/session: get by id: %w", err)
	}
	return &session, nil
}

func (r *SessionRepo) FindSession(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	err := gormutil.GetDB(ctx, r.db).Where(sessionByToken(token), "Token").Take(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/session: not found")
		}
		return nil, fmt.Errorf("gorm/session: get by token: %w", err)
	}
	return &session, nil
}

func (r *SessionRepo) UpdateSession(ctx context.Context, id string, data map[string]interface{}) (*models.Session, error) {
	db := gormutil.GetDB(ctx, r.db)
	result := db.Model(&models.Session{}).Where(sessionByID(id), "ID").Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/session: update: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, loc_errors.NotFoundErr("gorm/session: not found for update")
	}
	return r.FindSessionByID(ctx, id)
}

func (r *SessionRepo) DeleteSessionByID(ctx context.Context, id string) error {
	result := gormutil.GetDB(ctx, r.db).Where(sessionByID(id), "ID").Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("gorm/session: delete: %w", result.Error)
	}
	return nil
}

func (r *SessionRepo) DeleteSession(ctx context.Context, token string) error {
	result := gormutil.GetDB(ctx, r.db).Where(sessionByToken(token), "Token").Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("gorm/session: delete by token: %w", result.Error)
	}
	return nil
}

func (r *SessionRepo) DeleteUserSessions(ctx context.Context, userID string) error {
	result := gormutil.GetDB(ctx, r.db).Where(sessionsOfUser(userID), "UserID").Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("gorm/session: delete by user: %w", result.Error)
	}
	return nil
}

func (r *SessionRepo) DeleteExpiredSessions(ctx context.Context) error {
	result := gormutil.GetDB(ctx, r.db).
		Where(clause.Lt{Column: gormutil.Col(r.db, &models.Session{}, "ExpiresAt"), Value: time.Now().UTC()}).
		Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("gorm/session: delete expired: %w", result.Error)
	}
	return nil
}

func (r *SessionRepo) ListSessions(ctx context.Context, userID string) ([]models.Session, error) {
	var sessions []models.Session
	err := gormutil.GetDB(ctx, r.db).Where(sessionsOfUser(userID), "UserID").Find(&sessions).Error
	if err != nil {
		return nil, fmt.Errorf("gorm/session: list by user: %w", err)
	}
	return sessions, nil
}

func (r *SessionRepo) QuerySessions(ctx context.Context, filter models.SessionFilter, pagi dtos.PaginationInput) ([]models.Session, int64, error) {
	var sessions []models.Session
	var total int64

	db := gormutil.GetDB(ctx, r.db).Model(&models.Session{})
	if filter.UserId != "" {
		db = db.Where(sessionsOfUser(filter.UserId), "UserID")
	}
	if filter.ID != "" {
		db = db.Where(sessionByID(filter.ID), "ID")
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/session: count: %w", err)
	}

	limit := pagi.Limit
	if limit <= 0 {
		limit = 10
	}
	offset := (pagi.Page - 1) * limit
	if offset < 0 {
		offset = 0
	}

	err := db.Limit(limit).Offset(offset).Find(&sessions).Error
	if err != nil {
		return nil, 0, fmt.Errorf("gorm/session: list: %w", err)
	}
	return sessions, total, nil
}

// Struct conditions; pass the field name to Where so an empty value matches nothing instead of everything.
func sessionByID(id string) *models.Session        { return &models.Session{Base: models.Base{ID: id}} }
func sessionByToken(token string) *models.Session  { return &models.Session{Token: token} }
func sessionsOfUser(userID string) *models.Session { return &models.Session{UserID: userID} }
