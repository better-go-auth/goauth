// Package gormauthrepo provides GORM implementations for auth-domain repositories.
package gormauth

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
)

// AccountRepo implements corerepo.IOAuthAccountRepo using GORM.
type AccountRepo struct {
	db *gorm.DB
}

// NewAccountRepo creates a new GORM-backed AccountRepo.
func NewAccountRepo(db *gorm.DB) repo_interfaces.IOAuthAccountRepo {
	return &AccountRepo{db: db}
}

func (r *AccountRepo) CreateAccount(ctx context.Context, account *models.Account) (*models.Account, error) {
	if account.ID == "" {
		account.ID = models.NewID()
	}
	if err := gormutil.GetDB(ctx, r.db).Create(account).Error; err != nil {
		return nil, fmt.Errorf("gorm/account: create: %w", err)
	}
	return account, nil
}

func (r *AccountRepo) GetAccountByProviderAndAccountID(ctx context.Context, providerID models.Providers, accountID string) (*models.Account, error) {
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

func (r *AccountRepo) GetAccountByUserAndProvider(ctx context.Context, userID string, providerID models.Providers) (*models.Account, error) {
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

func (r *AccountRepo) UpdateAccount(ctx context.Context, id string, data map[string]interface{}) (*models.Account, error) {
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

func (r *AccountRepo) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	if err := gormutil.GetDB(ctx, r.db).Where("user_id = ?", userID).Delete(&models.Account{}).Error; err != nil {
		return fmt.Errorf("gorm/account: delete by user id: %w", err)
	}
	return nil
}

func (r *AccountRepo) DeleteAccountByUserAndProvider(ctx context.Context, userID, providerID string) error {
	if err := gormutil.GetDB(ctx, r.db).
		Where("user_id = ? AND provider_id = ?", userID, providerID).
		Delete(&models.Account{}).Error; err != nil {
		return fmt.Errorf("gorm/account: delete by user and provider: %w", err)
	}
	return nil
}

func (r *AccountRepo) ListAccountsByUserID(ctx context.Context, userID string) ([]models.Account, error) {
	var accounts []models.Account
	if err := gormutil.GetDB(ctx, r.db).Where("user_id = ?", userID).Find(&accounts).Error; err != nil {
		return nil, fmt.Errorf("gorm/account: list by user id: %w", err)
	}
	return accounts, nil
}
