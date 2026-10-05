// Package gormorg provides GORM implementations for org-domain repositories.
package gormorg

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/better-go-auth/goauth/src/common/gormutil"
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
	err := getDB(ctx, r.db).Where(orgByID(id), "ID").Take(&org).Error
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
	err := getDB(ctx, r.db).Where(&models.Organization{Slug: slug}, "Slug").Take(&org).Error
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
		Where(orgByID(id), "ID").
		Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/org: update: %w", result.Error)
	}
	return r.GetOrgByID(ctx, id)
}

func (r *OrgRepo) DeleteOrg(ctx context.Context, id string) error {
	db := getDB(ctx, r.db)
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(&models.Member{OrganizationID: id}, "OrganizationID").Delete(&models.Member{}).Error; err != nil {
			return fmt.Errorf("gorm/org: delete members: %w", err)
		}
		if err := tx.Where(&models.Invitation{OrganizationID: id}, "OrganizationID").Delete(&models.Invitation{}).Error; err != nil {
			return fmt.Errorf("gorm/org: delete invitations: %w", err)
		}
		if err := tx.Where(orgByID(id), "ID").Delete(&models.Organization{}).Error; err != nil {
			return fmt.Errorf("gorm/org: delete: %w", err)
		}
		return nil
	})
}

func (r *OrgRepo) ListOrgsByUserID(ctx context.Context, userID string) ([]models.Organization, error) {
	var orgs []models.Organization
	db := getDB(ctx, r.db)
	memberOrgIDs := db.Session(&gorm.Session{NewDB: true}).
		Model(&models.Member{}).
		Select(gormutil.Col(r.db, &models.Member{}, "OrganizationID").Name).
		Where(&models.Member{UserID: userID}, "UserID")
	err := db.
		Where(clause.Expr{SQL: "? IN (?)", Vars: []any{gormutil.Col(r.db, &models.Organization{}, "ID"), memberOrgIDs}}).
		Find(&orgs).Error
	if err != nil {
		return nil, fmt.Errorf("gorm/org: list by user id: %w", err)
	}
	return orgs, nil
}

func (r *OrgRepo) ListAllOrgs(ctx context.Context, status *models.OrgStatus, pagi models.Pagination) ([]models.Organization, int64, error) {
	var orgs []models.Organization
	var total int64

	org := &models.Organization{}
	q := getDB(ctx, r.db).Model(org)
	if status != nil {
		q = q.Where(&models.Organization{Status: *status}, "Status")
	}
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/org: list all count: %w", err)
	}
	sortBy, ok := orgSortFields[pagi.SortBy]
	if !ok {
		sortBy = "CreatedAt"
	}
	if err := q.Order(gormutil.OrderBy(r.db, org, sortBy, pagi.SortDir != "asc")).
		Limit(pagi.Limit).
		Offset(pagi.Offset).
		Find(&orgs).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/org: list all: %w", err)
	}
	return orgs, total, nil
}

// orgSortFields allowlists sortable API names and maps them to Go fields.
var orgSortFields = map[string]string{
	"createdAt": "CreatedAt", "created_at": "CreatedAt",
	"updatedAt": "UpdatedAt", "updated_at": "UpdatedAt",
	"name": "Name", "slug": "Slug", "status": "Status",
}

func orgByID(id string) *models.Organization {
	return &models.Organization{Base: coremodels.Base{ID: id}}
}
