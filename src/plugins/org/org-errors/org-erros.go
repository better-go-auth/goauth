package orgerrors

import (
	"net/http"

	errors "github.com/better-go-auth/goauth/src/common/autherr"
)

const (
	OrgNotFound        = errors.RespCode("ORGANIZATION_NOT_FOUND")
	MemberNotFound     = errors.RespCode("MEMBER_NOT_FOUND")
	InvitationNotFound = errors.RespCode("INVITATION_NOT_FOUND")
	InvitationExpired  = errors.RespCode("INVITATION_EXPIRED")
	AlreadyMember      = errors.RespCode("ALREADY_A_MEMBER")
	SlugTaken          = errors.RespCode("SLUG_TAKEN")
	OrgNotActive       = errors.RespCode("ORGANIZATION_NOT_ACTIVE")
	OrgPending         = errors.RespCode("ORGANIZATION_PENDING_APPROVAL")
	OrgSuspended       = errors.RespCode("ORGANIZATION_SUSPENDED")

	// Team Errors
	TeamNotFound              = errors.RespCode("TEAM_NOT_FOUND")
	TeamsDisabled             = errors.RespCode("TEAMS_DISABLED")
	MaximumTeamsReached       = errors.RespCode("MAXIMUM_TEAMS_REACHED")
	MaximumTeamMembersReached = errors.RespCode("MAXIMUM_TEAM_MEMBERS_REACHED")
	CannotRemoveAllTeams      = errors.RespCode("CANNOT_REMOVE_ALL_TEAMS")
	AlreadyTeamMember         = errors.RespCode("ALREADY_A_TEAM_MEMBER")
	TeamMemberNotFound        = errors.RespCode("TEAM_MEMBER_NOT_FOUND")

	// Dynamic Access Control Errors
	OrgRoleNotFound     = errors.RespCode("ORGANIZATION_ROLE_NOT_FOUND")
	MaximumRolesReached = errors.RespCode("MAXIMUM_ROLES_REACHED")

	// Limit & Validation Errors
	UserCannotCreateOrg          = errors.RespCode("USER_CANNOT_CREATE_ORG")
	OrganizationLimitReached     = errors.RespCode("ORGANIZATION_LIMIT_REACHED")
	MembershipLimitReached       = errors.RespCode("MEMBERSHIP_LIMIT_REACHED")
	InvitationLimitReached       = errors.RespCode("INVITATION_LIMIT_REACHED")
	OrganizationDeletionDisabled = errors.RespCode("ORGANIZATION_DELETION_DISABLED")
	EmailVerificationRequired    = errors.RespCode("EMAIL_NOT_VERIFIED")
	PendingInvitationExists      = errors.RespCode("PENDING_INVITATION_EXISTS")
	CannotLeaveAsSoleOwner       = errors.RespCode("CANNOT_LEAVE_AS_SOLE_OWNER")
)

var (
	// Org Errors
	ErrOrgNotFound               = errors.New(OrgNotFound, "Organization not found", http.StatusNotFound)
	ErrMemberNotFound            = errors.New(MemberNotFound, "Member not found in this organization", http.StatusNotFound)
	ErrInvitationNotFound        = errors.New(InvitationNotFound, "Invitation not found", http.StatusNotFound)
	ErrAlreadyMember             = errors.New(AlreadyMember, "User is already a member of this organization", http.StatusBadRequest)
	ErrInvitationExpired         = errors.New(InvitationExpired, "This invitation has expired", http.StatusBadRequest)
	ErrSlugTaken                 = errors.New(SlugTaken, "Organization slug is already taken", http.StatusUnprocessableEntity)
	ErrOrgNotActive              = errors.New(OrgNotActive, "Organization is not active", http.StatusForbidden)
	ErrOrgPending                = errors.New(OrgPending, "Organization is pending approval", http.StatusForbidden)
	ErrOrgSuspended              = errors.New(OrgSuspended, "Organization is suspended", http.StatusForbidden)
	ErrUserCannotCreateOrg       = errors.New(UserCannotCreateOrg, "User is not allowed to create an organization", http.StatusForbidden)
	ErrOrganizationLimitReached  = errors.New(OrganizationLimitReached, "You have reached the maximum number of organizations", http.StatusBadRequest)
	ErrMembershipLimitReached    = errors.New(MembershipLimitReached, "Organization has reached its membership limit", http.StatusBadRequest)
	ErrInvitationLimitReached    = errors.New(InvitationLimitReached, "Organization has reached its invitation limit", http.StatusBadRequest)
	ErrOrganizationDeletionDisabled = errors.New(OrganizationDeletionDisabled, "Organization deletion is disabled", http.StatusBadRequest)
	ErrEmailVerificationRequired = errors.New(EmailVerificationRequired, "Email verification is required for invitations", http.StatusForbidden)
	ErrPendingInvitationExists   = errors.New(PendingInvitationExists, "A pending invitation already exists for this email", http.StatusBadRequest)
	ErrCannotLeaveAsSoleOwner    = errors.New(CannotLeaveAsSoleOwner, "Cannot leave organization as the sole owner", http.StatusBadRequest)

	// Team Errors
	ErrTeamNotFound              = errors.New(TeamNotFound, "Team not found", http.StatusNotFound)
	ErrTeamsDisabled             = errors.New(TeamsDisabled, "Teams are not enabled", http.StatusNotFound)
	ErrMaximumTeamsReached       = errors.New(MaximumTeamsReached, "Maximum number of teams reached", http.StatusBadRequest)
	ErrMaximumTeamMembersReached = errors.New(MaximumTeamMembersReached, "Maximum number of team members reached", http.StatusBadRequest)
	ErrCannotRemoveAllTeams      = errors.New(CannotRemoveAllTeams, "Cannot remove all teams from organization", http.StatusBadRequest)
	ErrAlreadyTeamMember         = errors.New(AlreadyTeamMember, "User is already a member of this team", http.StatusBadRequest)
	ErrTeamMemberNotFound        = errors.New(TeamMemberNotFound, "Team member not found", http.StatusNotFound)

	// Dynamic Access Control Errors
	ErrOrgRoleNotFound     = errors.New(OrgRoleNotFound, "Organization role not found", http.StatusNotFound)
	ErrMaximumRolesReached = errors.New(MaximumRolesReached, "Maximum number of roles reached for this organization", http.StatusBadRequest)
)
