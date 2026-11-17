package gormauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	loc_errors "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// VerificationRepo implements repo_interfaces.IVerificationRepo using GORM.
type VerificationRepo struct {
	db         *gorm.DB
	generateID func() string
}

var _ repo_interfaces.IVerificationRepo = (*VerificationRepo)(nil)

// NewVerificationRepo creates a new GORM-backed VerificationRepo.
func NewVerificationRepo(db *gorm.DB, opts ...RepoOption) repo_interfaces.IVerificationRepo {
	cfg := &RepoConfig{}
	for _, o := range opts {
		o(cfg)
	}
	return &VerificationRepo{db: db, generateID: cfg.GenerateID}
}

func (r *VerificationRepo) newID() string {
	if r.generateID != nil {
		return r.generateID()
	}
	return models.NewID()
}

func (r *VerificationRepo) UpsertVerificationValue(ctx context.Context, verification *models.Verification) (*models.Verification, error) {
	// Step 1: Generate ID if not already provided
	if verification.ID == "" {
		verification.ID = r.newID()
	}
	// Step 2: Ensure timestamps are stored in UTC
	verification.EnsureUTC()
	// Step 3: Identifier is not unique in better-auth's schema, so replace instead of ON CONFLICT
	db := gormutil.GetDB(ctx, r.db)
	err := db.Transaction(func(tx *gorm.DB) error {
		tx = tx.WithContext(ctx)
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

func (r *VerificationRepo) FindVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
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

func (r *VerificationRepo) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error {
	result := gormutil.GetDB(ctx, r.db).Where(byIdentifier(identifier), "Identifier").Delete(&models.Verification{})
	if result.Error != nil {
		return fmt.Errorf("gorm/verification: delete: %w", result.Error)
	}
	return nil
}

func (r *VerificationRepo) ConsumeVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
	v, err := r.FindVerificationValue(ctx, identifier)
	if err != nil {
		return nil, err
	}
	// deleting by id makes the read-then-delete safe: only the caller whose delete hits the row wins
	res := gormutil.GetDB(ctx, r.db).Where(&models.Verification{Base: models.Base{ID: v.ID}}, "ID").Delete(&models.Verification{})
	if res.Error != nil {
		return nil, fmt.Errorf("gorm/verification: consume: %w", res.Error)
	}
	if res.RowsAffected == 0 || v.IsExpired() {
		return nil, loc_errors.NotFoundErr("gorm/verification: not found")
	}
	return v, nil
}

func (r *VerificationRepo) DeleteVerificationsByValue(ctx context.Context, identifierPrefix, value string) error {
	if identifierPrefix == "" || value == "" {
		return nil
	}
	db := gormutil.GetDB(ctx, r.db)
	escaped := strings.ReplaceAll(identifierPrefix, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "%", "\\%")
	escaped = strings.ReplaceAll(escaped, "_", "\\_")
	if err := db.Where("value = ? AND identifier LIKE ? ESCAPE '\\'", value, escaped+"%").Delete(&models.Verification{}).Error; err != nil {
		return fmt.Errorf("gorm/verification: delete by value: %w", err)
	}
	return nil
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func (r *VerificationRepo) DeleteExpiredVerifications(ctx context.Context) error {
	result := gormutil.GetDB(ctx, r.db).
		Where(clause.Lt{Column: gormutil.Col(r.db, &models.Verification{}, "ExpiresAt"), Value: time.Now().UTC()}).
		Delete(&models.Verification{})
	if result.Error != nil {
		return fmt.Errorf("gorm/verification: delete expired: %w", result.Error)
	}
	return nil
}

func (r *VerificationRepo) UpdateVerificationValue(ctx context.Context, id, oldValue, newValue string) (bool, error) {
	if id == "" {
		return false, nil
	}
	// Step 1: UPDATE ... WHERE id = ? AND value = ? is the compare-and-swap
	res := gormutil.GetDB(ctx, r.db).
		Model(&models.Verification{}).
		Where(&models.Verification{Base: models.Base{ID: id}, Value: oldValue}, "ID", "Value").
		Updates(map[string]interface{}{"Value": newValue, "UpdatedAt": time.Now().UTC()})
	if res.Error != nil {
		return false, fmt.Errorf("gorm/verification: update value: %w", res.Error)
	}
	// Step 2: no row matched → another request won the race
	return res.RowsAffected == 1, nil
}

func (r *VerificationRepo) DeleteVerificationIfValue(ctx context.Context, id, value string) (bool, error) {
	if id == "" {
		return false, nil
	}
	// DELETE ... WHERE id = ? AND value = ?: only one concurrent caller can delete the row
	res := gormutil.GetDB(ctx, r.db).
		Where(&models.Verification{Base: models.Base{ID: id}, Value: value}, "ID", "Value").
		Delete(&models.Verification{})
	if res.Error != nil {
		return false, fmt.Errorf("gorm/verification: delete if value: %w", res.Error)
	}
	return res.RowsAffected == 1, nil
}

func byIdentifier(identifier string) *models.Verification {
	return &models.Verification{Identifier: identifier}
}
