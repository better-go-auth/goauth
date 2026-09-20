package gormauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	loc_errors "github.com/better-go-auth/goauth/src/common/error"
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
	err := gormutil.GetDB(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "identifier"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "expires_at", "callback_url"}),
	}).Create(verification).Error
	if err != nil {
		return nil, fmt.Errorf("gorm/verification: upsert: %w", err)
	}
	return verification, nil
}

func (r *VerificationRepo) GetVerification(ctx context.Context, identifier string) (*models.Verification, error) {
	
	var v models.Verification
	err := gormutil.GetDB(ctx, r.db).Where("identifier = ?", identifier).Take(&v).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, loc_errors.NotFoundErr("gorm/verification: not found")
		}
		return nil, fmt.Errorf("gorm/verification: get: %w", err)
	}
	return &v, nil
}

func (r *VerificationRepo) DeleteVerification(ctx context.Context, identifier string) error {
	result := gormutil.GetDB(ctx, r.db).Where("identifier = ?", identifier).Delete(&models.Verification{})
	if result.Error != nil {
		return fmt.Errorf("gorm/verification: delete: %w", result.Error)
	}
	return nil
}

func (r *VerificationRepo) DeleteExpired(ctx context.Context) error {
	result := gormutil.GetDB(ctx, r.db).Where("expires_at < NOW()").Delete(&models.Verification{})
	if result.Error != nil {
		return fmt.Errorf("gorm/verification: delete expired: %w", result.Error)
	}
	return nil
}
