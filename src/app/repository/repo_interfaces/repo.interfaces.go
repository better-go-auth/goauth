package repo_interfaces

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/birukbelay/gocmn/src/dtos"
)

// IVerificationRepo defines the repository interface for verification codes and tokens.
type IVerificationRepo interface {
	// UpsertVerification inserts or updates a verification record matching the identifier.
	UpsertVerification(ctx context.Context, verification *models.Verification) (*models.Verification, error)
	// GetVerification fetches a verification record by identifier and purpose.
	GetVerification(ctx context.Context, identifier string) (*models.Verification, error)
	// DeleteVerification deletes a verification record by identifier and purpose.
	DeleteVerification(ctx context.Context, identifier string) error
	// DeleteExpired removes all expired verification records.
	DeleteExpired(ctx context.Context) error
}

// IOAuthAccountRepo defines the repository interface for OAuth Account persistence.
type IOAuthAccountRepo interface {
	// CreateAccount inserts a new account.
	CreateAccount(ctx context.Context, account *models.Account) (*models.Account, error)
	// GetAccountByProviderAndAccountID fetches an account by (providerId, accountId).
	GetAccountByProviderAndAccountID(ctx context.Context, providerID models.Providers, accountID string) (*models.Account, error)
	// GetAccountByUserAndProvider fetches a user's account for a specific provider.
	GetAccountByUserAndProvider(ctx context.Context, userID string, providerID models.Providers) (*models.Account, error)
	// UpdateAccount applies a partial update to an account.
	UpdateAccount(ctx context.Context, id string, data map[string]interface{}) (*models.Account, error)
	// DeleteAccountsByUserID removes all OAuth accounts for a user.
	DeleteAccountsByUserID(ctx context.Context, userID string) error
	// ListAccountsByUserID returns all accounts linked to a user.
	ListAccountsByUserID(ctx context.Context, userID string) ([]models.Account, error)
	// DeleteAccountByUserAndProvider removes a user's account for a specific provider
	// (used by Better Auth's /unlink-account).
	DeleteAccountByUserAndProvider(ctx context.Context, userID, providerID string) error
}

// UserFilter allows filtering user list queries.
type UserFilter struct {
	Email       *string `json:"email"`
	Role        *string `json:"role"`
	Banned      *bool   `json:"banned"`
	SearchField *string `json:"searchField"`
	SearchValue *string `json:"searchValue"`
}

// IUserRepo defines the repository interface for User persistence.
type IUserRepo interface {
	// CreateUser inserts a new user and returns the created record.
	CreateUser(ctx context.Context, user *models.User) (*models.User, error)
	// GetUserByID fetches a user by their ULID.
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	// GetUserByEmail fetches a user by email (case-insensitive).
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	// UpdateUser applies a partial update (map of column→value) and returns the updated record.
	UpdateUser(ctx context.Context, id string, data map[string]interface{}) (*models.User, error)
	// DeleteUser soft-deletes a user (sets DeletedAt).
	DeleteUser(ctx context.Context, id string) error
	// ListUsers returns a paginated list of users matching the filter.
	ListUsers(ctx context.Context, filter UserFilter, pagi dtos.PaginationInput) ([]models.User, int64, error)
}

type IAuthRepos interface {
	IOAuthAccountRepo
	IUserRepo
	ISessionRepo
	IVerificationRepo
}

type AuthRepos struct {
	IUserRepo
	IOAuthAccountRepo
	ISessionRepo
	IVerificationRepo
}
