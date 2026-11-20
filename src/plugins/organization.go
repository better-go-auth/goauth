package plugins

import (
	"context"
	"time"
)

// OrganizationMember is one membership of better-auth's `member` model (organization plugin).
type OrganizationMember struct {
	ID             string
	OrganizationID string
	UserID         string
	// Role is the stored role; several roles are comma-joined ("admin,sale") like better-auth's parseRoles.
	Role      string
	CreatedAt time.Time
}

// OrganizationStore is what other plugins read and write of the organization plugin's data: better-auth's
// plugins (sso, scim, ...) use ctx.context.adapter on the "member" and "organization" models when
// ctx.context.hasPlugin("organization"); goauth's organization plugin keeps those tables behind its own
// repositories, so it exposes them through this interface instead.
type OrganizationStore interface {
	// FindMember returns the membership of userID in organizationID, or (nil, nil) when there is none.
	FindMember(ctx context.Context, organizationID, userID string) (*OrganizationMember, error)
	// ListMembersByUser returns every membership of userID.
	ListMembersByUser(ctx context.Context, userID string) ([]OrganizationMember, error)
	// AddMember adds userID to organizationID with role and returns the new membership.
	AddMember(ctx context.Context, organizationID, userID, role string) (*OrganizationMember, error)
	// RemoveMember deletes the membership of userID in organizationID (no membership is not an error).
	RemoveMember(ctx context.Context, organizationID, userID string) error
	// FindOrganizationIDBySlug returns the id of the organization with slug, or "" when there is none.
	FindOrganizationIDBySlug(ctx context.Context, slug string) (string, error)
	// CreatorRole is the organization plugin's creatorRole option (default "owner").
	CreatorRole() string
}

// OrganizationStoreProvider is implemented by the organization plugin.
type OrganizationStoreProvider interface {
	OrganizationStore() OrganizationStore
}

// FindOrganizationStore returns the store of the installed organization plugin, or nil when none is installed
// (better-auth's `ctx.context.hasPlugin("organization")` is FindOrganizationStore(ps) != nil).
func FindOrganizationStore(ps []Plugin) OrganizationStore {
	for _, p := range ps {
		if sp, ok := p.(OrganizationStoreProvider); ok && sp != nil {
			if s := sp.OrganizationStore(); s != nil {
				return s
			}
		}
	}
	return nil
}
