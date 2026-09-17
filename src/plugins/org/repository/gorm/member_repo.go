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

// MemberRepo implements orgrepo.IMemberRepo using GORM.
type MemberRepo struct {
	db *gorm.DB
}

// NewMemberRepo creates a new GORM-backed MemberRepo.
func NewMemberRepo(db *gorm.DB) orgrepo.IMemberRepo {
	return &MemberRepo{db: db}
}

func (r *MemberRepo) CreateMember(ctx context.Context, member *models.Member) (*models.Member, error) {
	if member.ID == "" {
		member.ID = coremodels.NewID()
	}
	if err := getDB(ctx, r.db).Create(member).Error; err != nil {
		return nil, fmt.Errorf("gorm/member: create: %w", err)
	}
	return member, nil
}

func (r *MemberRepo) GetMemberByOrgAndUser(ctx context.Context, orgID, userID string) (*models.Member, error) {
	var member models.Member
	err := getDB(ctx, r.db).
		Preload("User").
		Where("organization_id = ? AND user_id = ?", orgID, userID).
		Take(&member).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/member: not found")
		}
		return nil, fmt.Errorf("gorm/member: get by org and user: %w", err)
	}
	return &member, nil
}

func (r *MemberRepo) GetMemberByID(ctx context.Context, id string) (*models.Member, error) {
	var member models.Member
	err := getDB(ctx, r.db).Preload("User").Where("id = ?", id).Take(&member).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/member: not found")
		}
		return nil, fmt.Errorf("gorm/member: get by id: %w", err)
	}
	return &member, nil
}

func (r *MemberRepo) UpdateMember(ctx context.Context, id string, data map[string]interface{}) (*models.Member, error) {
	result := getDB(ctx, r.db).
		Model(&models.Member{}).
		Where("id = ?", id).
		Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/member: update: %w", result.Error)
	}
	return r.GetMemberByID(ctx, id)
}

func (r *MemberRepo) DeleteMemberByID(ctx context.Context, id string) error {
	if err := getDB(ctx, r.db).Where("id = ?", id).Delete(&models.Member{}).Error; err != nil {
		return fmt.Errorf("gorm/member: delete by id: %w", err)
	}
	return nil
}

func (r *MemberRepo) DeleteMemberByOrgAndUser(ctx context.Context, orgID, userID string) error {
	if err := getDB(ctx, r.db).
		Where("organization_id = ? AND user_id = ?", orgID, userID).
		Delete(&models.Member{}).Error; err != nil {
		return fmt.Errorf("gorm/member: delete by org and user: %w", err)
	}
	return nil
}

func (r *MemberRepo) ListMembersByOrgID(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Member, int64, error) {
	query := getDB(ctx, r.db).
		Preload("User").
		Where("organization_id = ?", orgID)

	var total int64
	if err := query.Model(&models.Member{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/member: count: %w", err)
	}

	limit := 20
	if pagi.Limit > 0 {
		limit = pagi.Limit
	}

	var members []models.Member
	err := query.Limit(limit).Offset(pagi.Offset).Order("created_at desc").Find(&members).Error
	if err != nil {
		return nil, 0, fmt.Errorf("gorm/member: list: %w", err)
	}
	return members, total, nil
}
