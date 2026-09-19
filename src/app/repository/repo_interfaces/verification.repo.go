package repo_interfaces

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
)

// IVerificationRepo defines the repository interface for verification codes and tokens.
type IVerificationRepo interface {
	// UpsertVerification inserts or updates a verification record matching the identifier.
	UpsertVerification(ctx context.Context, verification *models.Verification) (*models.Verification, error)
	// GetVerification fetches a verification record by identifier and purpose.
	GetVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose) (*models.Verification, error)
	// DeleteVerification deletes a verification record by identifier and purpose.
	DeleteVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose) error
	// DeleteExpired removes all expired verification records.
	DeleteExpired(ctx context.Context) error
}
