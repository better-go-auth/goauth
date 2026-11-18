package apikey

import (
	"context"
	"errors"

	"github.com/better-go-auth/goauth/src/plugins/org"
	"github.com/better-go-auth/goauth/src/providers/access"
)

// orgAuthorizer implements OrganizationAuthorizer with goauth's organization plugin.
type orgAuthorizer struct {
	plugin *org.OrgPlugin
}

// OrganizationFrom connects organization-owned API keys (References: ReferencesOrganization) to goauth's
// organization plugin, like better-auth's lookup of the organization plugin: membership comes from the
// member table, and the member's role must grant apiKey:create / read / update / delete (the creator role,
// default "owner", is granted everything). The organization plugin is read lazily, so it may be listed
// after the api-key plugin.
//
//	orgPlugin, _ := org.New(org.OrgOptions{...})
//	keys := apikey.New(cfg, apikey.WithOrganization(apikey.OrganizationFrom(orgPlugin)))
func OrganizationFrom(p *org.OrgPlugin) OrganizationAuthorizer {
	return orgAuthorizer{plugin: p}
}

// MemberRole returns the user's role in the organization.
func (o orgAuthorizer) MemberRole(ctx context.Context, organizationID, userID string) (string, bool, error) {
	// Step 1: the plugin must be initialized
	if o.plugin == nil || o.plugin.Service() == nil {
		return "", false, errors.New("api-key: the organization plugin is not initialized")
	}
	// Step 2: the member row (not found = not a member)
	m, err := o.plugin.Service().GetMember(ctx, organizationID, userID)
	if err != nil || m == nil {
		return "", false, nil
	}
	return string(m.Role), true, nil
}

// HasPermission asks the organization plugin whether role grants request.
func (o orgAuthorizer) HasPermission(ctx context.Context, organizationID, role string, request access.Request) (bool, error) {
	if o.plugin == nil || o.plugin.Service() == nil {
		return false, errors.New("api-key: the organization plugin is not initialized")
	}
	return o.plugin.Service().HasPermissions(ctx, organizationID, role, request)
}

// CreatorRole returns the organization plugin's creator role (default "owner").
func (o orgAuthorizer) CreatorRole() string {
	if o.plugin == nil || o.plugin.Config.CreatorRole == "" {
		return "owner"
	}
	return o.plugin.Config.CreatorRole
}
