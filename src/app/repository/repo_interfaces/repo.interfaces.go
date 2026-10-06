package repo_interfaces

import (
	"context"
	"strings"

	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
)

// IUserRepo defines the repository interface for User persistence.
type IUserRepo interface {
	// CreateUser inserts a new user and returns the created record.
	CreateUser(ctx context.Context, user *models.User) (*models.User, error)
	// FindUserByID fetches a non-deleted user by id.
	FindUserByID(ctx context.Context, id string) (*models.User, error)
	// FindUserByEmail fetches a user by email (case-insensitive).
	FindUserByEmail(ctx context.Context, email string) (*models.User, error)
	// UpdateUser applies a partial update keyed by Go field name (e.g. "EmailVerified") and returns the updated record.
	UpdateUser(ctx context.Context, id string, data map[string]interface{}) (*models.User, error)
	// DeleteUser soft-deletes a user and frees their email.
	DeleteUser(ctx context.Context, id string) error
	// ListUsers returns a page of users matching the filter, plus the total count.
	ListUsers(ctx context.Context, filter UserFilter, pagi dtos.PaginationInput) ([]models.User, int64, error)
}

// IVerificationRepo defines the repository interface for verification codes and tokens.
type IVerificationRepo interface {
	// UpsertVerificationValue stores a verification, replacing any row with the same identifier.
	UpsertVerificationValue(ctx context.Context, verification *models.Verification) (*models.Verification, error)
	// FindVerificationValue fetches the newest verification for identifier.
	FindVerificationValue(ctx context.Context, identifier string) (*models.Verification, error)
	// DeleteVerificationByIdentifier deletes every verification with identifier.
	DeleteVerificationByIdentifier(ctx context.Context, identifier string) error
	// DeleteExpiredVerifications removes all expired verification records.
	DeleteExpiredVerifications(ctx context.Context) error
}

// IOAuthAccountRepo defines the repository interface for OAuth Account persistence.
type IOAuthAccountRepo interface {
	// CreateAccount inserts a new account.
	CreateAccount(ctx context.Context, account *models.Account) (*models.Account, error)
	// FindAccountByProviderID fetches an account by (providerId, accountId).
	FindAccountByProviderID(ctx context.Context, providerID models.Providers, accountID string) (*models.Account, error)
	// FindAccountByUserAndProvider fetches a user's account for a specific provider.
	FindAccountByUserAndProvider(ctx context.Context, userID string, providerID models.Providers) (*models.Account, error)
	// UpdateAccount applies a partial update to an account.
	UpdateAccount(ctx context.Context, id string, data map[string]interface{}) (*models.Account, error)
	// DeleteAccounts removes all OAuth accounts for a user.
	DeleteAccounts(ctx context.Context, userID string) error
	// FindAccounts returns all accounts linked to a user.
	FindAccounts(ctx context.Context, userID string) ([]models.Account, error)
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

// UserListField maps an allowed sort/search name (API or column spelling) to its models.User Go field.
func UserListField(field string) (string, bool) {
	switch strings.ToLower(field) {
	case "id":
		return "ID", true
	case "name":
		return "Name", true
	case "email":
		return "Email", true
	case "role":
		return "Role", true
	case "banned":
		return "Banned", true
	case "createdat", "created_at":
		return "CreatedAt", true
	case "updatedat", "updated_at":
		return "UpdatedAt", true
	case "lastloginat", "last_login_at":
		return "LastLoginAt", true
	default:
		return "", false
	}
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
