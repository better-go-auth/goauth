package services

import (
	"context"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/sso/config"
)

// memberRole is the role a provisioned user gets: getRole, else defaultRole, else "member".
func (s *Service) memberRole(ctx context.Context, data config.ProvisionUserData) (string, error) {
	op := s.cfg.OrganizationProvisioning
	if op != nil && op.GetRole != nil {
		return op.GetRole(ctx, data)
	}
	if op != nil && op.DefaultRole != "" {
		return op.DefaultRole, nil
	}
	return "member", nil
}

// assignOrganizationFromProvider is better-auth's assignOrganizationFromProvider: an SSO user joins the
// provider's organization (organization plugin installed, provisioning not disabled, not a member yet).
func (s *Service) assignOrganizationFromProvider(ctx context.Context, user *models.User, provider *config.Provider, rawAttributes map[string]any, token *providers.OAuth2Tokens) error {
	// Step 1: preconditions
	if provider.OrganizationID == "" {
		return nil
	}
	if op := s.cfg.OrganizationProvisioning; op != nil && op.Disabled {
		return nil
	}
	orgs := s.orgs()
	if orgs == nil {
		return nil
	}
	// Step 2: already a member
	m, err := orgs.FindMember(ctx, provider.OrganizationID, user.ID)
	if err != nil {
		return errorf("find member: %w", err)
	}
	if m != nil {
		return nil
	}
	// Step 3: the role, then the membership
	if rawAttributes == nil {
		rawAttributes = map[string]any{}
	}
	role, err := s.memberRole(ctx, config.ProvisionUserData{User: user, UserInfo: rawAttributes, Token: token, Provider: provider})
	if err != nil {
		return err
	}
	if _, err := orgs.AddMember(ctx, provider.OrganizationID, user.ID, role); err != nil {
		return errorf("add member: %w", err)
	}
	return nil
}

// AssignOrganizationByDomain is better-auth's assignOrganizationByDomain: after a non-SSO OAuth sign-in
// (/callback/{id}) the user joins the organization of the SSO provider that owns their email domain.
func (s *Service) AssignOrganizationByDomain(ctx context.Context, user *models.User) error {
	// Step 1: preconditions
	if op := s.cfg.OrganizationProvisioning; op != nil && op.Disabled {
		return nil
	}
	orgs := s.orgs()
	if orgs == nil || user == nil {
		return nil
	}
	parts := strings.SplitN(user.Email, "@", 2)
	if len(parts) < 2 || parts[1] == "" {
		return nil
	}
	domain := parts[1]
	// Step 2: the provider for the domain (exact match first, then comma lists / subdomains); only verified
	// domains when domain verification is on
	where := []adapter.Where{{Field: "domain", Value: domain}}
	verified := []adapter.Where{}
	if s.cfg.DomainVerification.Enabled {
		verified = append(verified, adapter.Where{Field: "domainVerified", Value: true})
		where = append(where, verified...)
	}
	var provider *config.Provider
	if r, err := s.store.FindOne(ctx, Model, where); err == nil {
		provider = providerFromRecord(r)
	}
	if provider == nil {
		all, err := s.listProviderRecords(ctx, verified)
		if err != nil {
			return errorf("list providers: %w", err)
		}
		for _, r := range all {
			if p := providerFromRecord(r); domainMatches(domain, p.Domain) {
				provider = p
				break
			}
		}
	}
	if provider == nil || provider.OrganizationID == "" {
		return nil
	}
	// Step 3: already a member
	m, err := orgs.FindMember(ctx, provider.OrganizationID, user.ID)
	if err != nil {
		return errorf("find member: %w", err)
	}
	if m != nil {
		return nil
	}
	// Step 4: the role, then the membership
	role, err := s.memberRole(ctx, config.ProvisionUserData{User: user, UserInfo: map[string]any{}, Provider: provider})
	if err != nil {
		return err
	}
	if _, err := orgs.AddMember(ctx, provider.OrganizationID, user.ID, role); err != nil {
		return errorf("add member: %w", err)
	}
	return nil
}
