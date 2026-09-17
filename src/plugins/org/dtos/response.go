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
	Metadata  *string `json:"metadata"`
	CreatedAt string  `json:"createdAt"`
}

// MemberResponse is the public member response.
type MemberResponse struct {
	ID             string                 `json:"id"`
	OrganizationID string                 `json:"organizationId"`
	UserID         string                 `json:"userId"`
	Role           string                 `json:"role"`
	User           *coredtos.UserResponse `json:"user,omitempty"`
	CreatedAt      string                 `json:"createdAt"`
}

// InvitationResponse is the public invitation response.
type InvitationResponse struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	Status         string `json:"status"`
	InviterID      string `json:"inviterId"`
	ExpiresAt      string `json:"expiresAt"`
	CreatedAt      string `json:"createdAt"`
}

// ─── Converters ──────────────────────────────────────────────────────────────

// OrgToResponse converts a models.Organization to an OrgResponse DTO.
func OrgToResponse(o *models.Organization) *OrgResponse {
	if o == nil {
		return nil
	}
	createdAt := ""
	if o.CreatedAt != nil {
		createdAt = o.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	}
	return &OrgResponse{
		ID:        o.ID,
		Name:      o.Name,
		Slug:      o.Slug,
		Logo:      o.Logo,
		Metadata:  o.Metadata,
		CreatedAt: createdAt,
	}
}

// MemberToResponse converts a models.Member to a MemberResponse DTO.
func MemberToResponse(m *models.Member) *MemberResponse {
	if m == nil {
		return nil
	}
	createdAt := ""
	if m.CreatedAt != nil {
		createdAt = m.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	}
	resp := &MemberResponse{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		UserID:         m.UserID,
		Role:           string(m.Role),
		CreatedAt:      createdAt,
	}
	if m.User != nil {
		resp.User = coredtos.UserToResponse(m.User)
	}
	return resp
}

// InvitationToResponse converts a models.Invitation to an InvitationResponse DTO.
func InvitationToResponse(i *models.Invitation) *InvitationResponse {
	if i == nil {
		return nil
	}
	createdAt := ""
	if i.CreatedAt != nil {
		createdAt = i.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z")
	}
	return &InvitationResponse{
		ID:             i.ID,
		OrganizationID: i.OrganizationID,
		Email:          i.Email,
		Role:           string(i.Role),
		Status:         string(i.Status),
		InviterID:      i.InviterID,
		ExpiresAt:      i.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999Z"),
		CreatedAt:      createdAt,
	}
}
