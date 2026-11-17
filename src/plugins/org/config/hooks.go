package config

import (
	"context"

	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
)

// ─── Organization Hook Data Payloads ──────────────────────────────────────────

type BeforeCreateOrgData struct {
	Organization dtos.CreateOrgInput
	User         *coremodels.User
}

type AfterCreateOrgData struct {
	Organization *models.Organization
	Member       *models.Member
	User         *coremodels.User
}

type BeforeUpdateOrgData struct {
	Organization dtos.UpdateOrgInput
	User         *coremodels.User
	Member       *models.Member
}

type AfterUpdateOrgData struct {
	Organization *models.Organization
	User         *coremodels.User
	Member       *models.Member
}

type BeforeDeleteOrgData struct {
	Organization *models.Organization
	User         *coremodels.User
}

type AfterDeleteOrgData struct {
	Organization *models.Organization
	User         *coremodels.User
}

// ─── Member Hook Data Payloads ────────────────────────────────────────────────

type BeforeAddMemberData struct {
	Member       models.Member
	User         *coremodels.User
	Organization *models.Organization
}

type AfterAddMemberData struct {
	Member       *models.Member
	User         *coremodels.User
	Organization *models.Organization
}

type BeforeRemoveMemberData struct {
	Member       *models.Member
	User         *coremodels.User
	Organization *models.Organization
}

type AfterRemoveMemberData struct {
	Member       *models.Member
	User         *coremodels.User
	Organization *models.Organization
}

type BeforeUpdateMemberRoleData struct {
	Member       *models.Member
	NewRole      string
	User         *coremodels.User
	Organization *models.Organization
}

type AfterUpdateMemberRoleData struct {
	Member       *models.Member
	PreviousRole string
	User         *coremodels.User
	Organization *models.Organization
}

// ─── Invitation Hook Data Payloads ────────────────────────────────────────────

type BeforeCreateInvitationData struct {
	Invitation   dtos.InviteMemberInput
	Inviter      *coremodels.User
	Organization *models.Organization
}

type AfterCreateInvitationData struct {
	Invitation   *models.Invitation
	Inviter      *coremodels.User
	Organization *models.Organization
}

type BeforeAcceptInvitationData struct {
	Invitation   *models.Invitation
	User         *coremodels.User
	Organization *models.Organization
}

type AfterAcceptInvitationData struct {
	Invitation   *models.Invitation
	Member       *models.Member
	User         *coremodels.User
	Organization *models.Organization
}

type BeforeRejectInvitationData struct {
	Invitation   *models.Invitation
	User         *coremodels.User
	Organization *models.Organization
}

type AfterRejectInvitationData struct {
	Invitation   *models.Invitation
	User         *coremodels.User
	Organization *models.Organization
}

type BeforeCancelInvitationData struct {
	Invitation   *models.Invitation
	CancelledBy  *coremodels.User
	Organization *models.Organization
}

type AfterCancelInvitationData struct {
	Invitation   *models.Invitation
	CancelledBy  *coremodels.User
	Organization *models.Organization
}

// ─── Team Hook Data Payloads ──────────────────────────────────────────────────

type BeforeCreateTeamData struct {
	Team         dtos.CreateTeamInput
	User         *coremodels.User
	Organization *models.Organization
}

type AfterCreateTeamData struct {
	Team         *models.Team
	User         *coremodels.User
	Organization *models.Organization
}

type BeforeUpdateTeamData struct {
	Team         *models.Team
	Updates      dtos.UpdateTeamInput
	User         *coremodels.User
	Organization *models.Organization
}

type AfterUpdateTeamData struct {
	Team         *models.Team
	User         *coremodels.User
	Organization *models.Organization
}

type BeforeDeleteTeamData struct {
	Team         *models.Team
	User         *coremodels.User
	Organization *models.Organization
}

type AfterDeleteTeamData struct {
	Team         *models.Team
	User         *coremodels.User
	Organization *models.Organization
}

type BeforeAddTeamMemberData struct {
	TeamMember   dtos.AddTeamMemberInput
	Team         *models.Team
	User         *coremodels.User
	Organization *models.Organization
}

type AfterAddTeamMemberData struct {
	TeamMember   *models.TeamMember
	Team         *models.Team
	User         *coremodels.User
	Organization *models.Organization
}

type BeforeRemoveTeamMemberData struct {
	TeamMember   *models.TeamMember
	Team         *models.Team
	User         *coremodels.User
	Organization *models.Organization
}

type AfterRemoveTeamMemberData struct {
	TeamMember   *models.TeamMember
	Team         *models.Team
	User         *coremodels.User
	Organization *models.Organization
}

// ─── OrganizationHooks Container ──────────────────────────────────────────────

// OrganizationHooks mirrors better-auth `organizationHooks` option containing lifecycle callbacks.
type OrganizationHooks struct {
	// Org lifecycle hooks
	BeforeCreateOrganization func(ctx context.Context, data BeforeCreateOrgData) (*dtos.CreateOrgInput, error)
	AfterCreateOrganization  func(ctx context.Context, data AfterCreateOrgData) error
	BeforeUpdateOrganization func(ctx context.Context, data BeforeUpdateOrgData) (*dtos.UpdateOrgInput, error)
	AfterUpdateOrganization  func(ctx context.Context, data AfterUpdateOrgData) error
	BeforeDeleteOrganization func(ctx context.Context, data BeforeDeleteOrgData) error
	AfterDeleteOrganization  func(ctx context.Context, data AfterDeleteOrgData) error

	// Member lifecycle hooks
	BeforeAddMember        func(ctx context.Context, data BeforeAddMemberData) (*models.Member, error)
	AfterAddMember         func(ctx context.Context, data AfterAddMemberData) error
	BeforeRemoveMember     func(ctx context.Context, data BeforeRemoveMemberData) error
	AfterRemoveMember      func(ctx context.Context, data AfterRemoveMemberData) error
	BeforeUpdateMemberRole func(ctx context.Context, data BeforeUpdateMemberRoleData) (*string, error)
	AfterUpdateMemberRole  func(ctx context.Context, data AfterUpdateMemberRoleData) error

	// Invitation lifecycle hooks
	BeforeCreateInvitation func(ctx context.Context, data BeforeCreateInvitationData) (*dtos.InviteMemberInput, error)
	AfterCreateInvitation  func(ctx context.Context, data AfterCreateInvitationData) error
	BeforeAcceptInvitation func(ctx context.Context, data BeforeAcceptInvitationData) error
	AfterAcceptInvitation  func(ctx context.Context, data AfterAcceptInvitationData) error
	BeforeRejectInvitation func(ctx context.Context, data BeforeRejectInvitationData) error
	AfterRejectInvitation  func(ctx context.Context, data AfterRejectInvitationData) error
	BeforeCancelInvitation func(ctx context.Context, data BeforeCancelInvitationData) error
	AfterCancelInvitation  func(ctx context.Context, data AfterCancelInvitationData) error

	// Team lifecycle hooks
	BeforeCreateTeam       func(ctx context.Context, data BeforeCreateTeamData) (*dtos.CreateTeamInput, error)
	AfterCreateTeam        func(ctx context.Context, data AfterCreateTeamData) error
	BeforeUpdateTeam       func(ctx context.Context, data BeforeUpdateTeamData) (*dtos.UpdateTeamInput, error)
	AfterUpdateTeam        func(ctx context.Context, data AfterUpdateTeamData) error
	BeforeDeleteTeam       func(ctx context.Context, data BeforeDeleteTeamData) error
	AfterDeleteTeam        func(ctx context.Context, data AfterDeleteTeamData) error
	BeforeAddTeamMember    func(ctx context.Context, data BeforeAddTeamMemberData) (*dtos.AddTeamMemberInput, error)
	AfterAddTeamMember     func(ctx context.Context, data AfterAddTeamMemberData) error
	BeforeRemoveTeamMember func(ctx context.Context, data BeforeRemoveTeamMemberData) error
	AfterRemoveTeamMember  func(ctx context.Context, data AfterRemoveTeamMemberData) error
}
