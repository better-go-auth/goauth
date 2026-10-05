package models

import (
	"time"

	coremodels "github.com/better-go-auth/goauth/src/models"
)

type OrgStatus string

const (
	OrgStatusActive    OrgStatus = "active"
	OrgStatusInactive  OrgStatus = "inactive"
	OrgStatusSuspended OrgStatus = "suspended"
	OrgStatusPending   OrgStatus = "pending"
)

// Organization is better-auth's `organization` model plus goauth's approval workflow.
type Organization struct {
	// ===== better-auth fields =====
	coremodels.Base         // id, createdAt, updatedAt
	Name            string  `json:"name"     gorm:"not null"             bun:"name,notnull"`
	Slug            string  `json:"slug"     gorm:"uniqueIndex;not null;size:255" bun:"slug,notnull,unique"`
	Logo            *string `json:"logo"                bun:"logo"`
	Metadata        *string `json:"metadata"            bun:"metadata"` // JSON string

	// ===== goauth fields (not in better-auth) =====
	Status OrgStatus `json:"status" gorm:"not null;default:active" bun:"status,notnull,default:active"`
	// CreatedBy is the creator and initial owner; empty for organizations created by better-auth.
	CreatedBy string `json:"createdBy" gorm:"index" bun:"created_by"`
}

func (Organization) TableName() string { return "organizations" }

// OrgMemberRole defines the roles available within an organization.
type OrgMemberRole string

func (s OrgMemberRole) String() string { return string(s) }

const (
	OrgRoleOwner  OrgMemberRole = "owner"
	OrgRoleAdmin  OrgMemberRole = "admin"
	OrgRoleMember OrgMemberRole = "member"
)

// Member is better-auth's `member` model: a user's role in an organization.
type Member struct {
	// ===== better-auth fields =====
	coremodels.Base               // id, createdAt (updatedAt is a goauth extra)
	OrganizationID  string        `json:"organizationId" gorm:"not null;index"         bun:"organization_id,notnull"`
	UserID          string        `json:"userId"         gorm:"not null;index"         bun:"user_id,notnull"`
	Role            OrgMemberRole `json:"role"           gorm:"not null;default:member" bun:"role,notnull,default:member"`

	// ===== goauth fields (not in better-auth) =====
	Organization *Organization    `json:"organization,omitempty" gorm:"foreignKey:OrganizationID;constraint:OnDelete:CASCADE" bun:"rel:belongs-to,join:organization_id=id"`
	User         *coremodels.User `json:"user,omitempty"         gorm:"foreignKey:UserID"                                    bun:"rel:belongs-to,join:user_id=id"`
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

// Invitation is better-auth's `invitation` model.
type Invitation struct {
	// ===== better-auth fields =====
	coremodels.Base                  // id, createdAt (updatedAt is a goauth extra)
	OrganizationID  string           `json:"organizationId" gorm:"not null;index"           bun:"organization_id,notnull"`
	Email           string           `json:"email"          gorm:"not null;index"           bun:"email,notnull"`
	Role            OrgMemberRole    `json:"role"           gorm:"not null;default:member"  bun:"role,notnull,default:member"`
	TeamID          *string          `json:"teamId,omitempty"                               bun:"team_id"`
	Status          InvitationStatus `json:"status"         gorm:"not null;default:pending" bun:"status,notnull,default:pending"`
	ExpiresAt       time.Time        `json:"expiresAt"                                      bun:"expires_at,notnull"`
	InviterID       string           `json:"inviterId"      gorm:"not null;index"           bun:"inviter_id,notnull"`

	// ===== goauth fields (not in better-auth) =====
	// AcceptedByID / AcceptedAt record who accepted the invitation and when.
	AcceptedByID *string          `json:"acceptedById"           bun:"accepted_by_id"`
	AcceptedAt   *time.Time       `json:"acceptedAt"             bun:"accepted_at"`
	Organization *Organization    `json:"organization,omitempty" gorm:"foreignKey:OrganizationID;constraint:OnDelete:CASCADE" bun:"rel:belongs-to,join:organization_id=id"`
	Inviter      *coremodels.User `json:"inviter,omitempty"      gorm:"foreignKey:InviterID"                                 bun:"rel:belongs-to,join:inviter_id=id"`
}

func (Invitation) TableName() string { return "invitations" }

// OrgPermission defines a fine-grained permission within an organization.
// To be deleted: replaced by better-auth's `organizationRole` table (dynamic access control).
// type OrgPermission struct {
// 	coremodels.Base
// 	OrganizationID string `json:"organizationId" gorm:"not null;index" bun:"organization_id,notnull"`
// 	Role           string `json:"role"           gorm:"not null"       bun:"role,notnull"`
// 	Resource       string `json:"resource"       gorm:"not null"       bun:"resource,notnull"` // e.g. "project", "billing"
// 	Action         string `json:"action"         gorm:"not null"       bun:"action,notnull"`   // e.g. "create", "read", "delete"
// }

// func (OrgPermission) TableName() string { return "org_permissions" }

// Pagination controls offset-based paginated queries.
type Pagination struct {
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
	SortBy  string `json:"sortBy"`  // column name
	SortDir string `json:"sortDir"` // "asc" | "desc"
}
