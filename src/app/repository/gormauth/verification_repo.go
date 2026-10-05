package gormauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	loc_errors "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// VerificationRepo implements repo_interfaces.IVerificationRepo using GORM.
type VerificationRepo struct {
	db *gorm.DB
}

var _ repo_interfaces.IVerificationRepo = (*VerificationRepo)(nil)

// NewVerificationRepo creates a new GORM-backed VerificationRepo.
func NewVerificationRepo(db *gorm.DB) repo_interfaces.IVerificationRepo {
	return &VerificationRepo{db: db}
}

func (r *VerificationRepo) UpsertVerification(ctx context.Context, verification *models.Verification) (*models.Verification, error) {
	if verification.ID == "" {
		verification.ID = models.NewID()
	}
	// identifier is not unique in better-auth's schema, so replace instead of ON CONFLICT
	err := gormutil.GetDB(ctx, r.db).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(byIdentifier(verification.Identifier), "Identifier").Delete(&models.Verification{}).Error; err != nil {
			return err
		}
		return tx.Create(verification).Error
	})
	if err != nil {
		return nil, fmt.Errorf("gorm/verification: upsert: %w", err)
	}
	return verification, nil
}

func (r *VerificationRepo) GetVerification(ctx context.Context, identifier string) (*models.Verification, error) {
	var v models.Verification
	err := gormutil.GetDB(ctx, r.db).
		Where(byIdentifier(identifier), "Identifier").
		Order(gormutil.OrderBy(r.db, &models.Verification{}, "CreatedAt", true)).
		Take(&v).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/verification: not found")
		}
		return nil, fmt.Errorf("gorm/verification: get: %w", err)
	}
	return &v, nil
}

func (r *VerificationRepo) DeleteVerification(ctx context.Context, identifier string) error {
	result := gormutil.GetDB(ctx, r.db).Where(byIdentifier(identifier), "Identifier").Delete(&models.Verification{})
	if result.Error != nil {
		return fmt.Errorf("gorm/verification: delete: %w", result.Error)
	}
	return nil
}

func (r *VerificationRepo) DeleteExpired(ctx context.Context) error {
	result := gormutil.GetDB(ctx, r.db).
		Where(clause.Lt{Column: gormutil.Col(r.db, &models.Verification{}, "ExpiresAt"), Value: time.Now().UTC()}).
		Delete(&models.Verification{})
	if result.Error != nil {
		return fmt.Errorf("gorm/verification: delete expired: %w", result.Error)
	}
	return nil
}

func byIdentifier(identifier string) *models.Verification {
	return &models.Verification{Identifier: identifier}
}
