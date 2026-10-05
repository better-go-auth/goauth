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
	// GetSessionByID fetches a session by its primary ID (the JWT `sid` for access/refresh sessions).
	GetSessionByID(ctx context.Context, id string) (*models.Session, error)
	// GetSessionByToken fetches a session by its token column.
	GetSessionByToken(ctx context.Context, token string) (*models.Session, error)
	// UpdateSession applies partial field updates to the session with the given id.
	UpdateSession(ctx context.Context, id string, data map[string]interface{}) (*models.Session, error)
	// DeleteSession deletes the session with the given id.
	DeleteSession(ctx context.Context, id string) error
	// DeleteSessionByToken deletes the session with the given token.
	DeleteSessionByToken(ctx context.Context, token string) error
	// DeleteSessionsByUserID deletes all sessions belonging to a user.
	DeleteSessionsByUserID(ctx context.Context, userID string) error
	// ListSessionsByUserID returns all active sessions for a user.
	ListSessionsByUserID(ctx context.Context, userID string) ([]models.Session, error)
	// ListSessions fetches paginated sessions matching the filter.
	ListSessions(ctx context.Context, filter models.SessionFilter, pagi dtos.PaginationInput) ([]models.Session, int64, error)
}
