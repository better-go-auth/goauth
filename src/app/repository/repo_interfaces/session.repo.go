package repo_interfaces

import (
	"context"

	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
)

// ISessionRepo defines the repository interface for Session persistence.
type ISessionRepo interface {
	// CreateSession inserts a new session record.
	CreateSession(ctx context.Context, session *models.Session) (*models.Session, error)
	// UpsertSession creates a session or updates listed fields on conflict by id.
	UpsertSession(ctx context.Context, session *models.Session) (*models.Session, error)
	// FindSessionByID fetches a session by its primary ID (the JWT `sid` for access/refresh sessions).
	FindSessionByID(ctx context.Context, id string) (*models.Session, error)
	// FindSession fetches a session by its token column.
	FindSession(ctx context.Context, token string) (*models.Session, error)
	// UpdateSession applies partial field updates to the session with the given id.
	UpdateSession(ctx context.Context, id string, data map[string]interface{}) (*models.Session, error)
	// DeleteSessionByID deletes the session with the given id.
	DeleteSessionByID(ctx context.Context, id string) error
	// DeleteSession deletes the session with the given token.
	DeleteSession(ctx context.Context, token string) error
	// DeleteUserSessions deletes all sessions belonging to a user.
	DeleteUserSessions(ctx context.Context, userID string) error
	// ListSessions returns every session of a user, expired ones included.
	ListSessions(ctx context.Context, userID string) ([]models.Session, error)
	// QuerySessions fetches paginated sessions matching the filter.
	QuerySessions(ctx context.Context, filter models.SessionFilter, pagi dtos.PaginationInput) ([]models.Session, int64, error)
	// DeleteExpiredSessions deletes sessions whose expiresAt has passed.
	DeleteExpiredSessions(ctx context.Context) error
}
