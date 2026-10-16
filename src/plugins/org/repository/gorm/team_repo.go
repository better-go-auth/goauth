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

// TeamRepo implements orgrepo.ITeamRepo using GORM.
type TeamRepo struct{ db *gorm.DB }

func NewTeamRepo(db *gorm.DB) orgrepo.ITeamRepo { return &TeamRepo{db: db} }

func (r *TeamRepo) CreateTeam(ctx context.Context, team *models.Team) (*models.Team, error) {
	if team.ID == "" {
		team.ID = coremodels.NewID()
	}
	if err := getDB(ctx, r.db).Create(team).Error; err != nil {
		return nil, fmt.Errorf("gorm/team: create: %w", err)
	}
	return team, nil
}

func (r *TeamRepo) GetTeamByID(ctx context.Context, id string) (*models.Team, error) {
	var team models.Team
	err := getDB(ctx, r.db).Where(&models.Team{Base: coremodels.Base{ID: id}}, "ID").Take(&team).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/team: not found")
		}
		return nil, fmt.Errorf("gorm/team: get: %w", err)
	}
	return &team, nil
}

func (r *TeamRepo) ListTeamsByOrgID(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Team, int64, error) {
	var teams []models.Team
	var total int64
	q := getDB(ctx, r.db).Model(&models.Team{}).Where(&models.Team{OrganizationID: orgID}, "OrganizationID")
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/team: count: %w", err)
	}
	if err := q.Limit(pagi.Limit).Offset(pagi.Offset).Order("created_at DESC").Find(&teams).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/team: list: %w", err)
	}
	return teams, total, nil
}

func (r *TeamRepo) UpdateTeam(ctx context.Context, id string, data map[string]interface{}) (*models.Team, error) {
	result := getDB(ctx, r.db).Model(&models.Team{}).Where(&models.Team{Base: coremodels.Base{ID: id}}, "ID").Updates(data)
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/team: update: %w", result.Error)
	}
	return r.GetTeamByID(ctx, id)
}

func (r *TeamRepo) DeleteTeam(ctx context.Context, id string) error {
	return getDB(ctx, r.db).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(&models.TeamMember{TeamID: id}, "TeamID").Delete(&models.TeamMember{}).Error; err != nil {
			return fmt.Errorf("gorm/team: delete members: %w", err)
		}
		if err := tx.Where(&models.Team{Base: coremodels.Base{ID: id}}, "ID").Delete(&models.Team{}).Error; err != nil {
			return fmt.Errorf("gorm/team: delete: %w", err)
		}
		return nil
	})
}

// TeamMemberRepo implements orgrepo.ITeamMemberRepo using GORM.
type TeamMemberRepo struct{ db *gorm.DB }

func NewTeamMemberRepo(db *gorm.DB) orgrepo.ITeamMemberRepo { return &TeamMemberRepo{db: db} }

func (r *TeamMemberRepo) CreateTeamMember(ctx context.Context, m *models.TeamMember) (*models.TeamMember, error) {
	if m.ID == "" {
		m.ID = coremodels.NewID()
	}
	if err := getDB(ctx, r.db).Create(m).Error; err != nil {
		return nil, fmt.Errorf("gorm/team-member: create: %w", err)
	}
	return m, nil
}

func (r *TeamMemberRepo) GetTeamMember(ctx context.Context, teamID, userID string) (*models.TeamMember, error) {
	var m models.TeamMember
	err := getDB(ctx, r.db).Where(&models.TeamMember{TeamID: teamID, UserID: userID}, "TeamID", "UserID").Take(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/team-member: not found")
		}
		return nil, fmt.Errorf("gorm/team-member: get: %w", err)
	}
	return &m, nil
}

func (r *TeamMemberRepo) ListMembersByTeamID(ctx context.Context, teamID string, pagi models.Pagination) ([]models.TeamMember, int64, error) {
	var out []models.TeamMember
	var total int64
	q := getDB(ctx, r.db).Model(&models.TeamMember{}).Where(&models.TeamMember{TeamID: teamID}, "TeamID")
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/team-member: count: %w", err)
	}
	if err := q.Limit(pagi.Limit).Offset(pagi.Offset).Order("created_at DESC").Find(&out).Error; err != nil {
		return nil, 0, fmt.Errorf("gorm/team-member: list: %w", err)
	}
	return out, total, nil
}

func (r *TeamMemberRepo) DeleteTeamMember(ctx context.Context, teamID, userID string) error {
	if err := getDB(ctx, r.db).Where(&models.TeamMember{TeamID: teamID, UserID: userID}, "TeamID", "UserID").Delete(&models.TeamMember{}).Error; err != nil {
		return fmt.Errorf("gorm/team-member: delete: %w", err)
	}
	return nil
}

// OrganizationRoleRepo implements orgrepo.IOrganizationRoleRepo using GORM.
type OrganizationRoleRepo struct{ db *gorm.DB }

func NewOrganizationRoleRepo(db *gorm.DB) orgrepo.IOrganizationRoleRepo {
	return &OrganizationRoleRepo{db: db}
}

func (r *OrganizationRoleRepo) CreateRole(ctx context.Context, role *models.OrganizationRole) (*models.OrganizationRole, error) {
	if role.ID == "" {
		role.ID = coremodels.NewID()
	}
	if err := getDB(ctx, r.db).Create(role).Error; err != nil {
		return nil, fmt.Errorf("gorm/org-role: create: %w", err)
	}
	return role, nil
}

func (r *OrganizationRoleRepo) GetRole(ctx context.Context, orgID, role string) (*models.OrganizationRole, error) {
	var out models.OrganizationRole
	err := getDB(ctx, r.db).Where(&models.OrganizationRole{OrganizationID: orgID, Role: role}, "OrganizationID", "Role").Take(&out).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("gorm/org-role: not found")
		}
		return nil, fmt.Errorf("gorm/org-role: get: %w", err)
	}
	return &out, nil
}

func (r *OrganizationRoleRepo) ListRolesByOrgID(ctx context.Context, orgID string) ([]models.OrganizationRole, error) {
	var out []models.OrganizationRole
	if err := getDB(ctx, r.db).Where(&models.OrganizationRole{OrganizationID: orgID}, "OrganizationID").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("gorm/org-role: list: %w", err)
	}
	return out, nil
}

func (r *OrganizationRoleRepo) UpdateRole(ctx context.Context, orgID, role string, permission string) (*models.OrganizationRole, error) {
	result := getDB(ctx, r.db).Model(&models.OrganizationRole{}).Where(&models.OrganizationRole{OrganizationID: orgID, Role: role}, "OrganizationID", "Role").Updates(map[string]interface{}{"Permission": permission})
	if result.Error != nil {
		return nil, fmt.Errorf("gorm/org-role: update: %w", result.Error)
	}
	return r.GetRole(ctx, orgID, role)
}

func (r *OrganizationRoleRepo) DeleteRole(ctx context.Context, orgID, role string) error {
	if err := getDB(ctx, r.db).Where(&models.OrganizationRole{OrganizationID: orgID, Role: role}, "OrganizationID", "Role").Delete(&models.OrganizationRole{}).Error; err != nil {
		return fmt.Errorf("gorm/org-role: delete: %w", err)
	}
	return nil
}
