package org

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/common/autherr"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	"gorm.io/gorm"
)

var _ plugin.OrganizationStoreProvider = (*OrgPlugin)(nil)

// OrganizationStore exposes the plugin's member and organization data to other plugins (sso, scim): what
// better-auth's plugins read and write through ctx.context.adapter on the "member" / "organization" models.
// It works before Init (the repositories are set when the plugin is built).
func (p *OrgPlugin) OrganizationStore() plugin.OrganizationStore { return orgStore{p: p} }

// orgStore implements plugin.OrganizationStore over the plugin's repositories.
type orgStore struct{ p *OrgPlugin }

// isNotFound reports a repository "not found" (the GORM repositories return plain errors for it).
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return true
	}
	if ae := autherr.AsAuthError(err); ae != nil && ae.StatusCode == http.StatusNotFound {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

func toMember(m *models.Member) *plugin.OrganizationMember {
	if m == nil {
		return nil
	}
	return &plugin.OrganizationMember{ID: m.ID, OrganizationID: m.OrganizationID, UserID: m.UserID, Role: string(m.Role), CreatedAt: m.CreatedAt}
}

// FindMember returns the membership of userID in organizationID, or (nil, nil).
func (s orgStore) FindMember(ctx context.Context, organizationID, userID string) (*plugin.OrganizationMember, error) {
	m, err := s.p.orgRepos.IMemberRepo.GetMemberByOrgAndUser(ctx, organizationID, userID)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return toMember(m), nil
}

// ListMembersByUser returns every membership of userID.
func (s orgStore) ListMembersByUser(ctx context.Context, userID string) ([]plugin.OrganizationMember, error) {
	// Step 1: the organizations the user belongs to
	orgs, err := s.p.orgRepos.IOrgRepo.ListOrgsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Step 2: the membership row of each
	out := make([]plugin.OrganizationMember, 0, len(orgs))
	for _, o := range orgs {
		m, err := s.FindMember(ctx, o.ID, userID)
		if err != nil {
			return nil, err
		}
		if m != nil {
			out = append(out, *m)
		}
	}
	return out, nil
}

// AddMember inserts a membership.
func (s orgStore) AddMember(ctx context.Context, organizationID, userID, role string) (*plugin.OrganizationMember, error) {
	now := time.Now().UTC()
	m := &models.Member{OrganizationID: organizationID, UserID: userID, Role: models.OrgMemberRole(role)}
	m.CreatedAt, m.UpdatedAt = now, now
	created, err := s.p.orgRepos.IMemberRepo.CreateMember(ctx, m)
	if err != nil {
		return nil, err
	}
	return toMember(created), nil
}

// RemoveMember deletes the membership of userID in organizationID.
func (s orgStore) RemoveMember(ctx context.Context, organizationID, userID string) error {
	if err := s.p.orgRepos.IMemberRepo.DeleteMemberByOrgAndUser(ctx, organizationID, userID); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// FindOrganizationIDBySlug returns the id of the organization with slug, or "".
func (s orgStore) FindOrganizationIDBySlug(ctx context.Context, slug string) (string, error) {
	o, err := s.p.orgRepos.IOrgRepo.GetOrgBySlug(ctx, slug)
	if err != nil {
		if isNotFound(err) {
			return "", nil
		}
		return "", err
	}
	if o == nil {
		return "", nil
	}
	return o.ID, nil
}

// CreatorRole is the configured creator role (default "owner").
func (s orgStore) CreatorRole() string {
	if r := s.p.Config.CreatorRole; r != "" {
		return r
	}
	return string(models.OrgRoleOwner)
}
