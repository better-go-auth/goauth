package repoimpl

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
)

// IOAuthAccountRepo defines the repository interface for OAuth Account persistence.
type IOAuthAccountRepo interface {
	// Create inserts a new account.
	Create(ctx context.Context, account *models.Account) (*models.Account, error)
	// GetByProviderAndAccountID fetches an account by (providerId, accountId).
	GetByProviderAndAccountID(ctx context.Context, providerID models.Providers, accountID string) (*models.Account, error)
	// GetByUserAndProvider fetches a user's account for a specific provider.
	GetByUserAndProvider(ctx context.Context, userID string, providerID models.Providers) (*models.Account, error)
	// Update applies a partial update to an account.
	Update(ctx context.Context, id string, data map[string]interface{}) (*models.Account, error)
	// DeleteByUserID removes all OAuth accounts for a user.
	DeleteByUserID(ctx context.Context, userID string) error
	// ListByUserID returns all accounts linked to a user.
	ListByUserID(ctx context.Context, userID string) ([]models.Account, error)
	// DeleteByUserAndProvider removes a user's account for a specific provider
	// (used by Better Auth's /unlink-account).
	DeleteByUserAndProvider(ctx context.Context, userID, providerID string) error
}
