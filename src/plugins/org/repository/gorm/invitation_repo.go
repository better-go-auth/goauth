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

// InvitationRepo implements orgrepo.IInvitationRepo using GORM.
type InvitationRepo struct {
	db *gorm.DB
}

// NewInvitationRepo creates a new GORM-backed InvitationRepo.
func NewInvitationRepo(db *gorm.DB) orgrepo.IInvitationRepo {
	return &InvitationRepo{db: db}
}

func (r *InvitationRepo) CreateInvitation(ctx context.Context, inv *models.Invitation) (*models.Invitation, error) {
	if inv.ID == "" {
		inv.ID = coremodels.NewID()
	}
	if err := getDB(ctx, r.db).Create(inv).Error; err != nil {
		return nil, fmt.Errorf("gorm/invitation: create: %w", err)
	}
	return inv, nil
}

func (r *InvitationRepo) GetInvitationByID(ctx context.Context, id string) (*models.Invitation, error) {
	var inv models.Invitation
	err := getDB(ctx, r.db).
		Preload("Organization").
		Preload("Inviter").
		Where("id = ?", id).Take(&inv).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/invitation: not found")
		}
		return nil, fmt.Errorf("gorm/invitation: get by id: %w", err)
	}
	return &inv, nil
}

func (r *InvitationRepo) GetInvitationByOrgAndEmail(ctx context.Context, orgID, email string) (*models.Invitation, error) {
	var inv models.Invitation
	err := getDB(ctx, r.db).
		Where("organization_id = ? AND LOWER(email) = LOWER(?) AND status = 'pending'", orgID, email).
		Take(&inv).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/invitation: not found")
		}
		return nil, fmt.Errorf("gorm/invitation: get by org and email: %w", err)
	}
	return &inv, nil
}

func (r *InvitationRepo) UpdateInvitation(ctx context.Context, id string, data map[string]interface{}) (*models.Invitation, error) {
	if err := getDB(ctx, r.db).
		Model(&models.Invitation{}).
		Where("id = ?", id).
		Updates(data).Error; err != nil {
		return nil, fmt.Errorf("gorm/invitation: update: %w", err)
	}
	return r.GetInvitationByID(ctx, id)
}

func (r *InvitationRepo) DeleteInvitationByID(ctx context.Context, id string) error {
	if err := getDB(ctx, r.db).Where("id = ?", id).Delete(&models.Invitation{}).Error; err != nil {
		return fmt.Errorf("gorm/invitation: delete: %w", err)
	}
	return nil
}

func (r *InvitationRepo) ListInvitationsByOrgID(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Invitation, int64, error) {
	query := getDB(ctx, r.db).
		Preload("Inviter").
		Where("organization_id = ?", orgID)

	var total int64
	if err := query.Model(&models.Invitation{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/invitation: count: %w", err)
	}

	limit := 20
	if pagi.Limit > 0 {
		limit = pagi.Limit
	}

	var invitations []models.Invitation
	err := query.Limit(limit).Offset(pagi.Offset).Order("created_at desc").Find(&invitations).Error
	if err != nil {
		return nil, 0, fmt.Errorf("gorm/invitation: list: %w", err)
	}
	return invitations, total, nil
}

func (r *InvitationRepo) ListInvitationsByEmail(ctx context.Context, email string) ([]models.Invitation, error) {
	var invitations []models.Invitation
	err := getDB(ctx, r.db).
		Preload("Organization").
		Preload("Inviter").
		Where("LOWER(email) = LOWER(?) AND status = 'pending' AND expires_at > NOW()", email).
		Find(&invitations).Error
	if err != nil {
		return nil, fmt.Errorf("gorm/invitation: list by email: %w", err)
	}
	return invitations, nil
}
