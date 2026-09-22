package models

import (
	"time"

	coremodels "github.com/better-go-auth/goauth/src/models"
)

// Organization represents a multi-tenant workspace (matching better-auth org plugin).
type Organization struct {
	coremodels.Base

	Name     string  `json:"name"   gorm:"not null;size:255"    bun:"name,notnull"`
	Slug     string  `json:"slug"   gorm:"uniqueIndex;not null;size:100" bun:"slug,notnull,unique"`
	Logo     *string `json:"logo"   gorm:"size:2048"            bun:"logo"`
	Metadata *string `json:"metadata" gorm:"type:text"        bun:"metadata"` // JSON string

	// The user who created this organization (and is its initial owner).
	CreatedBy string `json:"createdBy" gorm:"not null;size:26;index" bun:"created_by,notnull"`
}

func (Organization) TableName() string { return "organizations" }

// OrgMemberRole defines the roles available within an organization.
type OrgMemberRole string

func (s OrgMemberRole) String() string { return string(s) }

const (
	OrgRoleOwner  OrgMemberRole = "owner"
	OrgRoleAdmin  OrgMemberRole = "org_admin"
	OrgRoleMember OrgMemberRole = "member"
)

// Member links a user to an organization with a role.
type Member struct {
	coremodels.Base

	OrganizationID string        `json:"organizationId" gorm:"not null;index;size:26"          bun:"organization_id,notnull"`
	Organization   *Organization `json:"organization,omitempty" gorm:"foreignKey:OrganizationID;constraint:OnDelete:CASCADE" bun:"rel:belongs-to,join:organization_id=id"`

	UserID string           `json:"userId" gorm:"not null;index;size:26" bun:"user_id,notnull"`
	User   *coremodels.User `json:"user,omitempty" gorm:"foreignKey:UserID" bun:"rel:belongs-to,join:user_id=id"`

	Role OrgMemberRole `json:"role" gorm:"not null;size:50;default:member" bun:"role,notnull,default:member"`
}

func (Member) TableName() string { return "members" }

// InvitationStatus tracks the state of an invitation.
type InvitationStatus string

const (
	InvitationPending  InvitationStatus = "pending"
	InvitationAccepted InvitationStatus = "accepted"
	InvitationRejected InvitationStatus = "rejected"
	InvitationCanceled InvitationStatus = "canceled"
	InvitationExpired  InvitationStatus = "expired"
)

// Invitation represents an org invite sent to an email address.
type Invitation struct {
	coremodels.Base

	OrganizationID string        `json:"organizationId" gorm:"not null;index;size:26"              bun:"organization_id,notnull"`
	Organization   *Organization `json:"organization,omitempty" gorm:"foreignKey:OrganizationID;constraint:OnDelete:CASCADE"   bun:"rel:belongs-to,join:organization_id=id"`

	// Who sent the invite
	InviterID string           `json:"inviterId" gorm:"not null;size:26;index"  bun:"inviter_id,notnull"`
	Inviter   *coremodels.User `json:"inviter,omitempty" gorm:"foreignKey:InviterID" bun:"rel:belongs-to,join:inviter_id=id"`

	Email  string           `json:"email"  gorm:"not null;size:255;index"       bun:"email,notnull"`
	Role   OrgMemberRole    `json:"role"   gorm:"not null;size:50;default:member" bun:"role,notnull,default:member"`
	Status InvitationStatus `json:"status" gorm:"not null;size:20;default:pending" bun:"status,notnull,default:pending"`

	ExpiresAt time.Time `json:"expiresAt" bun:"expires_at,notnull"`

	// The user who acted on the invitation (accepted/rejected)
	AcceptedByID *string    `json:"acceptedById" gorm:"size:26" bun:"accepted_by_id"`
	AcceptedAt   *time.Time `json:"acceptedAt"                  bun:"accepted_at"`
}

func (Invitation) TableName() string { return "invitations" }

// OrgPermission defines a fine-grained permission within an organization.
// Used for custom RBAC beyond the default owner/admin/member roles.
type OrgPermission struct {
	coremodels.Base
	OrganizationID string `json:"organizationId" gorm:"not null;index;size:26" bun:"organization_id,notnull"`
	Role           string `json:"role"           gorm:"not null;size:50"        bun:"role,notnull"`
	Resource       string `json:"resource"       gorm:"not null;size:100"       bun:"resource,notnull"` // e.g. "project", "billing"
	Action         string `json:"action"         gorm:"not null;size:50"        bun:"action,notnull"`   // e.g. "create", "read", "delete"
}

func (OrgPermission) TableName() string { return "org_permissions" }

// Pagination controls offset-based paginated queries.
type Pagination struct {
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
	SortBy  string `json:"sortBy"`  // column name
	SortDir string `json:"sortDir"` // "asc" | "desc"
}
