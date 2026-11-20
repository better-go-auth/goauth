package dtos

import (
	coredtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
)

// OrgResponse is the public organization response.
type OrgResponse struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Slug      string  `json:"slug"`
	Logo      *string `json:"logo"`
	Metadata  any     `json:"metadata"`
	Status    string  `json:"status"`
	CreatedBy string  `json:"createdBy"`
	OrgType   *string `json:"orgType,omitempty"`
	CreatedAt string  `json:"createdAt"`
}

// MemberResponse is the public member response.
type MemberResponse struct {
	ID             string      `json:"id"`
	OrganizationID string      `json:"organizationId"`
	UserID         string      `json:"userId"`
	Role           string      `json:"role"`
	User           *MemberUser `json:"user,omitempty"`
	CreatedAt      string      `json:"createdAt"`
}

// MemberUser is the user attached to a member by better-auth's org adapter: only id, name, email and image.
type MemberUser struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Email string  `json:"email"`
	Image *string `json:"image"`
}

// FullOrgResponse is better-auth's get-full-organization response: the organization with its members
// (and their users), its invitations and, when teams are enabled, its teams.
type FullOrgResponse struct {
	OrgResponse
	Members     []MemberResponse     `json:"members"`
	Invitations []InvitationResponse `json:"invitations"`
	// Teams is set (possibly to an empty list) only when the teams feature is enabled.
	Teams *[]TeamResponse `json:"teams,omitempty"`
}

// CreatedOrgResponse is better-auth's create response: the organization plus the creator's membership.
type CreatedOrgResponse struct {
	OrgResponse
	Members []MemberResponse `json:"members"`
}

// RemovedMemberResponse is better-auth's remove-member response.
type RemovedMemberResponse struct {
	Member MemberResponse `json:"member"`
}

// InvitationResultResponse is better-auth's accept-invitation / reject-invitation response
// (member is null on reject).
type InvitationResultResponse struct {
	Invitation *InvitationResponse `json:"invitation"`
	Member     *MemberResponse     `json:"member"`
}

// InvitationDetailsResponse is better-auth's get-invitation response: the invitation plus the
// organization name and slug and the inviter's email.
type InvitationDetailsResponse struct {
	InvitationResponse
	InviterEmail string `json:"inviterEmail"`
}

// ActiveMemberRoleResponse is better-auth's get-active-member-role response.
type ActiveMemberRoleResponse struct {
	Role string `json:"role"`
}

// OrgMessageResponse is the {message} body of better-auth's remove-team and remove-team-member. The name is unique among goauth's
// plugins because Huma names OpenAPI schemas after the Go type.
type OrgMessageResponse struct {
	Message string `json:"message"`
}

// MessageResponse is OrgMessageResponse (the name earlier goauth versions used).
type MessageResponse = OrgMessageResponse

// InvitationResponse is the public invitation response.
type InvitationResponse struct {
	ID               string                 `json:"id"`
	OrganizationID   string                 `json:"organizationId"`
	OrganizationName *string                `json:"organizationName,omitempty"`
	OrganizationSlug *string                `json:"organizationSlug,omitempty"`
	Email            string                 `json:"email"`
	Role             string                 `json:"role"`
	Status           string                 `json:"status"`
	InviterID        string                 `json:"inviterId"`
	TeamID           *string                `json:"teamId"`
	Inviter          *coredtos.UserResponse `json:"inviter,omitempty"`
	ExpiresAt        string                 `json:"expiresAt"`
	CreatedAt        string                 `json:"createdAt"`
}

// ─── Converters ──────────────────────────────────────────────────────────────

// OrgToResponse converts a models.Organization to an OrgResponse DTO.
func OrgToResponse(o *models.Organization) *OrgResponse {
	if o == nil {
		return nil
	}
	createdAt := o.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	return &OrgResponse{
		ID:        o.ID,
		Name:      o.Name,
		Slug:      o.Slug,
		Logo:      o.Logo,
		Metadata:  MetadataOutput(o.Metadata),
		Status:    string(o.Status),
		CreatedBy: o.CreatedBy,
		OrgType:   o.OrgType,
		CreatedAt: createdAt,
	}
}

// MemberToResponse converts a models.Member to a MemberResponse DTO.
func MemberToResponse(m *models.Member) *MemberResponse {
	if m == nil {
		return nil
	}
	createdAt := m.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	resp := &MemberResponse{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		UserID:         m.UserID,
		Role:           string(m.Role),
		CreatedAt:      createdAt,
	}
	if m.User != nil {
		resp.User = &MemberUser{ID: m.User.ID, Name: m.User.Name, Email: m.User.Email, Image: m.User.Image}
	}
	return resp
}

// MemberWithoutUser returns the member response without the joined user (better-auth's raw member row,
// as returned by update-member-role, accept-invitation and create).
func MemberWithoutUser(m *models.Member) *MemberResponse {
	resp := MemberToResponse(m)
	if resp != nil {
		resp.User = nil
	}
	return resp
}

// InvitationToResponse converts a models.Invitation to an InvitationResponse DTO.
func InvitationToResponse(i *models.Invitation) *InvitationResponse {
	if i == nil {
		return nil
	}
	createdAt := i.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	resp := &InvitationResponse{
		ID:             i.ID,
		OrganizationID: i.OrganizationID,
		Email:          i.Email,
		Role:           string(i.Role),
		Status:         string(i.Status),
		InviterID:      i.InviterID,
		TeamID:         i.TeamID,
		ExpiresAt:      i.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999Z"),
		CreatedAt:      createdAt,
	}
	if i.Organization != nil {
		name := i.Organization.Name
		slug := i.Organization.Slug
		resp.OrganizationName = &name
		resp.OrganizationSlug = &slug
	}
	if i.Inviter != nil {
		u := coredtos.UserFromModel(i.Inviter)
		resp.Inviter = &u
	}
	return resp
}

// TeamResponse is the public team response.
type TeamResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	OrganizationID string `json:"organizationId"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}

// TeamMemberResponse is the public team member response.
type TeamMemberResponse struct {
	ID        string                 `json:"id"`
	TeamID    string                 `json:"teamId"`
	UserID    string                 `json:"userId"`
	User      *coredtos.UserResponse `json:"user,omitempty"`
	CreatedAt string                 `json:"createdAt"`
}

// OrgRoleResponse is the public organization role response.
type OrgRoleResponse struct {
	ID             string            `json:"id"`
	OrganizationID string            `json:"organizationId"`
	Role           string            `json:"role"`
	Permission     models.Permission `json:"permission"`
	Ops            models.Operations `json:"ops,omitempty"`
	CreatedAt      string            `json:"createdAt"`
	UpdatedAt      string            `json:"updatedAt"`
}

// TeamToResponse converts a models.Team to a TeamResponse DTO.
func TeamToResponse(t *models.Team) *TeamResponse {
	if t == nil {
		return nil
	}
	createdAt := t.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	updatedAt := t.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	return &TeamResponse{
		ID:             t.ID,
		Name:           t.Name,
		OrganizationID: t.OrganizationID,
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
	}
}

// TeamMemberToResponse converts a models.TeamMember to a TeamMemberResponse DTO.
func TeamMemberToResponse(m *models.TeamMember) *TeamMemberResponse {
	if m == nil {
		return nil
	}
	createdAt := m.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	resp := &TeamMemberResponse{
		ID:        m.ID,
		TeamID:    m.TeamID,
		UserID:    m.UserID,
		CreatedAt: createdAt,
	}
	if m.User != nil {
		u := coredtos.UserFromModel(m.User)
		resp.User = &u
	}
	return resp
}

// OrgRoleToResponse converts a models.OrganizationRole to an OrgRoleResponse DTO.
func OrgRoleToResponse(r *models.OrganizationRole) *OrgRoleResponse {
	if r == nil {
		return nil
	}
	createdAt := r.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	updatedAt := r.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	return &OrgRoleResponse{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		Role:           r.Role,
		Permission:     r.Permission,
		Ops:            r.Ops,
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
	}
}
