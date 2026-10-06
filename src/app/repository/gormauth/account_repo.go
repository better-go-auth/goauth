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

func (r *AccountRepo) FindAccountByProviderID(ctx context.Context, providerID models.Providers, accountID string) (*models.Account, error) {
	var account models.Account
	err := gormutil.GetDB(ctx, r.db).
		Where(&models.Account{ProviderID: providerID, AccountID: accountID}, "ProviderID", "AccountID").
		Take(&account).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/account: not found")
		}
		return nil, fmt.Errorf("gorm/account: get by provider: %w", err)
	}
	return &account, nil
}

func (r *AccountRepo) FindAccountByUserAndProvider(ctx context.Context, userID string, providerID models.Providers) (*models.Account, error) {
	var account models.Account
	err := gormutil.GetDB(ctx, r.db).
		Where(&models.Account{UserID: userID, ProviderID: providerID}, "UserID", "ProviderID").
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
		Where(accountByID(id), "ID").
		Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/account: update: %w", result.Error)
	}
	var account models.Account
	if err := gormutil.GetDB(ctx, r.db).Where(accountByID(id), "ID").Take(&account).Error; err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *AccountRepo) DeleteAccounts(ctx context.Context, userID string) error {
	if err := gormutil.GetDB(ctx, r.db).Where(&models.Account{UserID: userID}, "UserID").Delete(&models.Account{}).Error; err != nil {
		return fmt.Errorf("gorm/account: delete by user id: %w", err)
	}
	return nil
}

func (r *AccountRepo) DeleteAccountByUserAndProvider(ctx context.Context, userID, providerID string) error {
	if err := gormutil.GetDB(ctx, r.db).
		Where(&models.Account{UserID: userID, ProviderID: models.Providers(providerID)}, "UserID", "ProviderID").
		Delete(&models.Account{}).Error; err != nil {
		return fmt.Errorf("gorm/account: delete by user and provider: %w", err)
	}
	return nil
}

func (r *AccountRepo) FindAccounts(ctx context.Context, userID string) ([]models.Account, error) {
	var accounts []models.Account
	if err := gormutil.GetDB(ctx, r.db).Where(&models.Account{UserID: userID}, "UserID").Find(&accounts).Error; err != nil {
		return nil, fmt.Errorf("gorm/account: list by user id: %w", err)
	}
	return accounts, nil
}

func accountByID(id string) *models.Account {
	return &models.Account{Base: models.Base{ID: id}}
}
