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

	// Dynamic Access Control Errors (better-auth ORGANIZATION_ERROR_CODES)
	OrgRoleNotFound     = errors.RespCode("ROLE_NOT_FOUND")
	MaximumRolesReached = errors.RespCode("TOO_MANY_ROLES")

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
	ErrOrgNotFound                  = errors.New(OrgNotFound, "Organization not found", http.StatusNotFound)
	ErrMemberNotFound               = errors.New(MemberNotFound, "Member not found in this organization", http.StatusNotFound)
	ErrInvitationNotFound           = errors.New(InvitationNotFound, "Invitation not found", http.StatusNotFound)
	ErrAlreadyMember                = errors.New(AlreadyMember, "User is already a member of this organization", http.StatusBadRequest)
	ErrInvitationExpired            = errors.New(InvitationExpired, "This invitation has expired", http.StatusBadRequest)
	ErrSlugTaken                    = errors.New(SlugTaken, "Organization slug is already taken", http.StatusUnprocessableEntity)
	ErrOrgNotActive                 = errors.New(OrgNotActive, "Organization is not active", http.StatusForbidden)
	ErrOrgPending                   = errors.New(OrgPending, "Organization is pending approval", http.StatusForbidden)
	ErrOrgSuspended                 = errors.New(OrgSuspended, "Organization is suspended", http.StatusForbidden)
	ErrUserCannotCreateOrg          = errors.New(UserCannotCreateOrg, "User is not allowed to create an organization", http.StatusForbidden)
	ErrOrganizationLimitReached     = errors.New(OrganizationLimitReached, "You have reached the maximum number of organizations", http.StatusBadRequest)
	ErrMembershipLimitReached       = errors.New(MembershipLimitReached, "Organization has reached its membership limit", http.StatusBadRequest)
	ErrInvitationLimitReached       = errors.New(InvitationLimitReached, "Organization has reached its invitation limit", http.StatusBadRequest)
	ErrOrganizationDeletionDisabled = errors.New(OrganizationDeletionDisabled, "Organization deletion is disabled", http.StatusBadRequest)
	ErrEmailVerificationRequired    = errors.New(EmailVerificationRequired, "Email verification is required for invitations", http.StatusForbidden)
	ErrPendingInvitationExists      = errors.New(PendingInvitationExists, "A pending invitation already exists for this email", http.StatusBadRequest)
	ErrCannotLeaveAsSoleOwner       = errors.New(CannotLeaveAsSoleOwner, "Cannot leave organization as the sole owner", http.StatusBadRequest)

	// Team Errors
	ErrTeamNotFound              = errors.New(TeamNotFound, "Team not found", http.StatusNotFound)
	ErrTeamsDisabled             = errors.New(TeamsDisabled, "Teams are not enabled", http.StatusNotFound)
	ErrMaximumTeamsReached       = errors.New(MaximumTeamsReached, "Maximum number of teams reached", http.StatusBadRequest)
	ErrMaximumTeamMembersReached = errors.New(MaximumTeamMembersReached, "Maximum number of team members reached", http.StatusBadRequest)
	ErrCannotRemoveAllTeams      = errors.New(CannotRemoveAllTeams, "Cannot remove all teams from organization", http.StatusBadRequest)
	ErrAlreadyTeamMember         = errors.New(AlreadyTeamMember, "User is already a member of this team", http.StatusBadRequest)
	ErrTeamMemberNotFound        = errors.New(TeamMemberNotFound, "Team member not found", http.StatusNotFound)

	// Dynamic Access Control Errors
	ErrOrgRoleNotFound     = errors.New(OrgRoleNotFound, "Role not found", http.StatusBadRequest)
	ErrMaximumRolesReached = errors.New(MaximumRolesReached, "This organization has too many roles", http.StatusBadRequest)

	// better-auth organization access-control error codes
	ErrNoActiveOrganization         = errors.New("NO_ACTIVE_ORGANIZATION", "No active organization", http.StatusBadRequest)
	ErrUserNotMemberOfOrganization  = errors.New("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization", http.StatusUnauthorized)
	ErrNotAMemberOfThisOrganization = errors.New("YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION", "You are not a member of this organization", http.StatusForbidden)
	ErrMissingACInstance            = errors.New("MISSING_AC_INSTANCE", "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information", http.StatusNotImplemented)
	ErrMustBeInOrgToCreateRole      = errors.New("YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE", "You must be in an organization to create a role", http.StatusBadRequest)
	ErrNotAllowedToCreateRole       = errors.New("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE", "You are not allowed to create a role", http.StatusForbidden)
	ErrNotAllowedToUpdateRole       = errors.New("YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE", "You are not allowed to update a role", http.StatusForbidden)
	ErrNotAllowedToDeleteRole       = errors.New("YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE", "You are not allowed to delete a role", http.StatusForbidden)
	ErrNotAllowedToReadRole         = errors.New("YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE", "You are not allowed to read a role", http.StatusForbidden)
	ErrNotAllowedToListRole         = errors.New("YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE", "You are not allowed to list a role", http.StatusForbidden)
	ErrInvalidResource              = errors.New("INVALID_RESOURCE", "The provided permission includes an invalid resource", http.StatusBadRequest)
	ErrRoleNameIsAlreadyTaken       = errors.New("ROLE_NAME_IS_ALREADY_TAKEN", "That role name is already taken", http.StatusBadRequest)
	ErrCannotDeleteAPreDefinedRole  = errors.New("CANNOT_DELETE_A_PRE_DEFINED_ROLE", "Cannot delete a pre-defined role", http.StatusBadRequest)
	ErrRoleIsAssignedToMembers      = errors.New("ROLE_IS_ASSIGNED_TO_MEMBERS", "Cannot delete a role that is assigned to members. Please reassign the members to a different role first", http.StatusBadRequest)
)
