package repository

import (
	"context"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/models/migration"

	"github.com/better-go-auth/goauth/src/plugins/admin/dtos"
)

// IAdminRepo defines repository methods needed by the Admin plugin.
type IAdminRepo interface {
	// ListUsers searches, filters, and paginates users according to admin criteria.
	ListUsers(ctx context.Context, input dtos.AdminListUsersInput) ([]models.User, int64, error)
	// CreateUserWithAccount inserts a new user and their credential account in a transaction.
	CreateUserWithAccount(ctx context.Context, user *models.User, passwordHash string) (*models.User, error)
	// SetUserPassword updates the password hash in the user's credential account.
	SetUserPassword(ctx context.Context, userID, passwordHash string) error
	// SetUserRole changes a user's role and returns the updated user.
	SetUserRole(ctx context.Context, userID string, role enums.Role) (*models.User, error)
	// BanUser marks a user as banned with an optional reason and expiry timestamp.
	BanUser(ctx context.Context, userID string, reason *string, expiresAt *time.Time) (*models.User, error)
	// UnbanUser clears a user's ban status.
	UnbanUser(ctx context.Context, userID string) (*models.User, error)
	// RemoveUser deletes a user, their linked accounts, and their active sessions.
	RemoveUser(ctx context.Context, userID string) error
	// ListUserSessions returns all active, non-expired sessions for a user.
	ListUserSessions(ctx context.Context, userID string) ([]models.Session, error)
	// RevokeUserSession deletes a single session by its ID or token.
	RevokeUserSession(ctx context.Context, sessionID, sessionToken string) error
	// RevokeUserSessions deletes all sessions belonging to a specific user.
	RevokeUserSessions(ctx context.Context, userID string) error
	// CreateImpersonationSession creates an impersonation session with impersonatedBy set.
	CreateImpersonationSession(ctx context.Context, session *models.Session) (*models.Session, error)
	// GetSessionByToken retrieves a session by its token (including associated User).
	GetSessionByToken(ctx context.Context, token string) (*models.Session, error)
	// DeleteSessionByID deletes a session by ID.
	DeleteSessionByID(ctx context.Context, id string) error
	// GetUserByID retrieves a user by ID.
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	// GetUserByEmail retrieves a user by email.
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
}

// AdminRepositories bundles the repositories and migrator for the Admin plugin.
type AdminRepositories struct {
	AdminRepo IAdminRepo
	Migrator  migration.IMigrator
}
