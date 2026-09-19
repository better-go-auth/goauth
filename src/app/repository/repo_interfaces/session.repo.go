package repo_interfaces

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/birukbelay/gocmn/src/dtos"
)

// ISessionRepo defines the repository interface for Session persistence.
type ISessionRepo interface {
	// CreateSession inserts a new session record.
	CreateSession(ctx context.Context, session *models.Session) (*models.Session, error)
	// UpsertSession creates a session or updates listed fields on conflict by session_id.
	UpsertSession(ctx context.Context, session *models.Session) (*models.Session, error)
	// GetSessionByID fetches a session by its primary ID.
	GetSessionByID(ctx context.Context, id string) (*models.Session, error)
	// GetSessionBySessionID fetches a session by its unique session_id (token).
	GetSessionBySessionID(ctx context.Context, sessionID string) (*models.Session, error)
	// GetSessionByToken searches for a session by either session_id or hashed_token.
	GetSessionByToken(ctx context.Context, token string) (*models.Session, error)
	// UpdateSession applies partial field updates to a session.
	UpdateSession(ctx context.Context, sessionID string, data map[string]interface{}) (*models.Session, error)
	// DeleteSession deletes a single session by session_id.
	DeleteSession(ctx context.Context, sessionID string) error
	// DeleteSessionsByUserID deletes all sessions belonging to a user.
	DeleteSessionsByUserID(ctx context.Context, userID string) error
	// ListSessionsByUserID returns all active sessions for a user.
	ListSessionsByUserID(ctx context.Context, userID string) ([]models.Session, error)
	// ListSessions fetches paginated sessions matching the filter.
	ListSessions(ctx context.Context, filter models.SessionFilter, pagi dtos.PaginationInput) ([]models.Session, int64, error)
}
