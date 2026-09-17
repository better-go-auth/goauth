// Package gormorg provides GORM implementations for org-domain repositories.
package gormorg

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
)

// OrgRepo implements orgrepo.IOrgRepo using GORM.
type OrgRepo struct {
	db *gorm.DB
}

// NewOrgRepo creates a new GORM-backed OrgRepo.
func NewOrgRepo(db *gorm.DB) orgrepo.IOrgRepo {
	return &OrgRepo{db: db}
}

func (r *OrgRepo) CreateOrg(ctx context.Context, org *models.Organization) (*models.Organization, error) {
	if org.ID == "" {
		org.ID = coremodels.NewID()
	}
	if err := getDB(ctx, r.db).Create(org).Error; err != nil {
		return nil, fmt.Errorf("gorm/org: create: %w", err)
	}
	return org, nil
}

func (r *OrgRepo) GetOrgByID(ctx context.Context, id string) (*models.Organization, error) {
	var org models.Organization
	err := getDB(ctx, r.db).Where("id = ?", id).Take(&org).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/org: not found")
		}
		return nil, fmt.Errorf("gorm/org: get by id: %w", err)
	}
	return &org, nil
}

func (r *OrgRepo) GetOrgBySlug(ctx context.Context, slug string) (*models.Organization, error) {
	var org models.Organization
	err := getDB(ctx, r.db).Where("slug = ?", slug).Take(&org).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/org: not found")
		}
		return nil, fmt.Errorf("gorm/org: get by slug: %w", err)
	}
	return &org, nil
}

func (r *OrgRepo) UpdateOrg(ctx context.Context, id string, data map[string]interface{}) (*models.Organization, error) {
	result := getDB(ctx, r.db).
		Model(&models.Organization{}).
		Where("id = ?", id).
		Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/org: update: %w", result.Error)
	}
	return r.GetOrgByID(ctx, id)
}

func (r *OrgRepo) DeleteOrg(ctx context.Context, id string) error {
	if err := getDB(ctx, r.db).Where("id = ?", id).Delete(&models.Organization{}).Error; err != nil {
		return fmt.Errorf("gorm/org: delete: %w", err)
	}
	return nil
}

func (r *OrgRepo) ListOrgsByUserID(ctx context.Context, userID string) ([]models.Organization, error) {
	var orgs []models.Organization
	err := getDB(ctx, r.db).
		Joins("JOIN members ON members.organization_id = organizations.id").
		Where("members.user_id = ?", userID).
		Find(&orgs).Error
	if err != nil {
		return nil, fmt.Errorf("gorm/org: list by user id: %w", err)
	}
	return orgs, nil
}
