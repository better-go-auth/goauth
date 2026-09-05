// Package gormauthrepo provides GORM implementations for auth-domain repositories.
package gormauthrepo

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/app/repoimpl"
	"github.com/better-go-auth/goauth/src/common/gormutil"
)

// AccountRepo implements repoimpl.IOAuthAccountRepo using GORM.
type AccountRepo struct {
	db *gorm.DB
}

// NewAccountRepo creates a new GORM-backed AccountRepo.
func NewAccountRepo(db *gorm.DB) repoimpl.IOAuthAccountRepo {
	return &AccountRepo{db: db}
}

func (r *AccountRepo) Create(ctx context.Context, account *models.Account) (*models.Account, error) {
	if account.ID == "" {
		account.ID = models.NewID()
	}
	if err := gormutil.GetDB(ctx, r.db).Create(account).Error; err != nil {
		return nil, fmt.Errorf("gorm/account: create: %w", err)
	}
	return account, nil
}

func (r *AccountRepo) GetByProviderAndAccountID(ctx context.Context, providerID models.Providers, accountID string) (*models.Account, error) {
	var account models.Account
	err := gormutil.GetDB(ctx, r.db).
		Where(models.Account{ProviderId: providerID, AccountID: accountID}).
		Take(&account).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/account: not found")
		}
		return nil, fmt.Errorf("gorm/account: get by provider: %w", err)
	}
	return &account, nil
}

func (r *AccountRepo) GetByUserAndProvider(ctx context.Context, userID string, providerID models.Providers) (*models.Account, error) {
	var account models.Account
	err := gormutil.GetDB(ctx, r.db).
		Where(models.Account{UserID: userID, ProviderId: providerID}).
		Take(&account).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/account: not found")
		}
		return nil, fmt.Errorf("gorm/account: get by user and provider: %w", err)
	}
	return &account, nil
}

func (r *AccountRepo) Update(ctx context.Context, id string, data map[string]interface{}) (*models.Account, error) {
	result := gormutil.GetDB(ctx, r.db).
		Model(&models.Account{}).
		Where("id = ?", id).
		Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/account: update: %w", result.Error)
	}
	var account models.Account
	if err := gormutil.GetDB(ctx, r.db).Where("id = ?", id).Take(&account).Error; err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *AccountRepo) DeleteByUserID(ctx context.Context, userID string) error {
	if err := gormutil.GetDB(ctx, r.db).Where("user_id = ?", userID).Delete(&models.Account{}).Error; err != nil {
		return fmt.Errorf("gorm/account: delete by user id: %w", err)
	}
	return nil
}

func (r *AccountRepo) DeleteByUserAndProvider(ctx context.Context, userID, providerID string) error {
	if err := gormutil.GetDB(ctx, r.db).
		Where("user_id = ? AND provider_id = ?", userID, providerID).
		Delete(&models.Account{}).Error; err != nil {
		return fmt.Errorf("gorm/account: delete by user and provider: %w", err)
	}
	return nil
}

func (r *AccountRepo) ListByUserID(ctx context.Context, userID string) ([]models.Account, error) {
	var accounts []models.Account
	if err := gormutil.GetDB(ctx, r.db).Where("user_id = ?", userID).Find(&accounts).Error; err != nil {
		return nil, fmt.Errorf("gorm/account: list by user id: %w", err)
	}
	return accounts, nil
}
