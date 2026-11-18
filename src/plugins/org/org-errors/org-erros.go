package orgerrors

import (
	"net/http"

	errors "github.com/better-go-auth/goauth/src/common/autherr"
)

const (
	// Codes follow better-auth's ORGANIZATION_ERROR_CODES (plugins/organization/error-codes.ts).
	OrgNotFound        = errors.RespCode("ORGANIZATION_NOT_FOUND")
	MemberNotFound     = errors.RespCode("MEMBER_NOT_FOUND")
	InvitationNotFound = errors.RespCode("INVITATION_NOT_FOUND")
	// InvitationExpired is kept for API compatibility: expired invitations answer INVITATION_NOT_FOUND like better-auth.
	InvitationExpired = errors.RespCode("INVITATION_NOT_FOUND")
	AlreadyMember     = errors.RespCode("USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION")
	SlugTaken         = errors.RespCode("ORGANIZATION_SLUG_ALREADY_TAKEN")
	OrgAlreadyExists  = errors.RespCode("ORGANIZATION_ALREADY_EXISTS")
	// goauth-only organization statuses (approval workflow)
	OrgNotActive = errors.RespCode("ORGANIZATION_NOT_ACTIVE")
	OrgPending   = errors.RespCode("ORGANIZATION_PENDING_APPROVAL")
	OrgSuspended = errors.RespCode("ORGANIZATION_SUSPENDED")

	// Team Errors
	TeamNotFound              = errors.RespCode("TEAM_NOT_FOUND")
	TeamsDisabled             = errors.RespCode("TEAMS_DISABLED")
	MaximumTeamsReached       = errors.RespCode("YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS")
	MaximumTeamMembersReached = errors.RespCode("TEAM_MEMBER_LIMIT_REACHED")
	CannotRemoveAllTeams      = errors.RespCode("UNABLE_TO_REMOVE_LAST_TEAM")
	// AlreadyTeamMember is no longer returned by add-team-member (better-auth returns the existing membership).
	AlreadyTeamMember  = errors.RespCode("ALREADY_A_TEAM_MEMBER")
	TeamMemberNotFound = errors.RespCode("USER_IS_NOT_A_MEMBER_OF_THE_TEAM")

	// Dynamic Access Control Errors (better-auth ORGANIZATION_ERROR_CODES)
	OrgRoleNotFound     = errors.RespCode("ROLE_NOT_FOUND")
	MaximumRolesReached = errors.RespCode("TOO_MANY_ROLES")

	// Limit & Validation Errors
	UserCannotCreateOrg          = errors.RespCode("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION")
	OrganizationLimitReached     = errors.RespCode("YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS")
	MembershipLimitReached       = errors.RespCode("ORGANIZATION_MEMBERSHIP_LIMIT_REACHED")
	InvitationLimitReached       = errors.RespCode("INVITATION_LIMIT_REACHED")
	OrganizationDeletionDisabled = errors.RespCode("ORGANIZATION_DELETION_DISABLED")
	EmailVerificationRequired    = errors.RespCode("EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION")
	PendingInvitationExists      = errors.RespCode("USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION")
	CannotLeaveAsSoleOwner       = errors.RespCode("YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
)

var (
	// Org Errors (codes, messages and statuses as in better-auth)
	ErrOrgNotFound                  = errors.New(OrgNotFound, "Organization not found", http.StatusBadRequest)
	ErrMemberNotFound               = errors.New(MemberNotFound, "Member not found", http.StatusBadRequest)
	ErrInvitationNotFound           = errors.New(InvitationNotFound, "Invitation not found", http.StatusBadRequest)
	ErrAlreadyMember                = errors.New(AlreadyMember, "User is already a member of this organization", http.StatusBadRequest)
	ErrInvitationExpired            = errors.New(InvitationExpired, "Invitation not found", http.StatusBadRequest)
	ErrSlugTaken                    = errors.New(SlugTaken, "Organization slug already taken", http.StatusBadRequest)
	ErrOrgAlreadyExists             = errors.New(OrgAlreadyExists, "Organization already exists", http.StatusBadRequest)
	ErrOrgNotActive                 = errors.New(OrgNotActive, "Organization is not active", http.StatusForbidden)
	ErrOrgPending                   = errors.New(OrgPending, "Organization is pending approval", http.StatusForbidden)
	ErrOrgSuspended                 = errors.New(OrgSuspended, "Organization is suspended", http.StatusForbidden)
	ErrUserCannotCreateOrg          = errors.New(UserCannotCreateOrg, "You are not allowed to create a new organization", http.StatusForbidden)
	ErrOrganizationLimitReached     = errors.New(OrganizationLimitReached, "You have reached the maximum number of organizations", http.StatusForbidden)
	ErrMembershipLimitReached       = errors.New(MembershipLimitReached, "Organization membership limit reached", http.StatusForbidden)
	ErrInvitationLimitReached       = errors.New(InvitationLimitReached, "Invitation limit reached", http.StatusForbidden)
	ErrOrganizationDeletionDisabled = errors.New(OrganizationDeletionDisabled, "Organization deletion is disabled", http.StatusNotFound)
	ErrEmailVerificationRequired    = errors.New(EmailVerificationRequired, "Email verification required before accepting or rejecting invitation", http.StatusForbidden)
	// ErrEmailVerificationRequiredForInvitation is returned by get-invitation and list-user-invitations.
	ErrEmailVerificationRequiredForInvitation = errors.New("EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION", "Email verification required to view or list invitations for the session email", http.StatusForbidden)
	ErrPendingInvitationExists                = errors.New(PendingInvitationExists, "User is already invited to this organization", http.StatusBadRequest)
	ErrCannotLeaveAsSoleOwner                 = errors.New(CannotLeaveAsSoleOwner, "You cannot leave the organization as the only owner", http.StatusBadRequest)
	ErrCannotLeaveWithoutOwner                = errors.New("YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER", "You cannot leave the organization without an owner", http.StatusBadRequest)
	ErrNotRecipientOfInvitation               = errors.New("YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION", "You are not the recipient of the invitation", http.StatusForbidden)
	ErrInviterNoLongerMember                  = errors.New("INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION", "Inviter is no longer a member of the organization", http.StatusBadRequest)
	ErrFailedToRetrieveInvitation             = errors.New("FAILED_TO_RETRIEVE_INVITATION", "Failed to retrieve invitation", http.StatusBadRequest)

	// Permission errors of the individual better-auth routes
	ErrNotAllowedToUpdateOrganization = errors.New("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION", "You are not allowed to update this organization", http.StatusForbidden)
	ErrNotAllowedToDeleteOrganization = errors.New("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION", "You are not allowed to delete this organization", http.StatusForbidden)
	ErrNotAllowedToInviteUsers        = errors.New("YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION", "You are not allowed to invite users to this organization", http.StatusForbidden)
	ErrNotAllowedToInviteWithRole     = errors.New("YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE", "You are not allowed to invite a user with this role", http.StatusForbidden)
	ErrNotAllowedToCancelInvitation   = errors.New("YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION", "You are not allowed to cancel this invitation", http.StatusForbidden)
	ErrNotAllowedToUpdateMember       = errors.New("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER", "You are not allowed to update this member", http.StatusForbidden)
	// ErrNotAllowedToDeleteMember is 401, as in better-auth's remove-member.
	ErrNotAllowedToDeleteMember       = errors.New("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER", "You are not allowed to delete this member", http.StatusUnauthorized)
	ErrNotAllowedToCreateTeams        = errors.New("YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION", "You are not allowed to create teams in this organization", http.StatusForbidden)
	ErrNotAllowedToUpdateTeam         = errors.New("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM", "You are not allowed to update this team", http.StatusForbidden)
	ErrNotAllowedToDeleteThisTeam     = errors.New("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM", "You are not allowed to delete this team", http.StatusForbidden)
	ErrNotAllowedToDeleteTeams        = errors.New("YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION", "You are not allowed to delete teams in this organization", http.StatusForbidden)
	ErrNotAllowedToCreateTeamMember   = errors.New("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER", "You are not allowed to create a new member", http.StatusForbidden)
	ErrNotAllowedToRemoveTeamMember   = errors.New("YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER", "You are not allowed to remove a team member", http.StatusForbidden)
	ErrNotAllowedToAccessOrganization = errors.New("YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION", "You are not allowed to access this organization as an owner", http.StatusForbidden)
	// ErrUserNotMemberOfOrg400 / ErrUserNotMemberOfOrg403 are better-auth's USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION
	// with the status of the route that throws it.
	ErrUserNotMemberOfOrg400 = errors.New("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization", http.StatusBadRequest)
	ErrUserNotMemberOfOrg403 = errors.New("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization", http.StatusForbidden)
	// ErrUserNotFoundBadRequest is better-auth's APIError.fromStatus("BAD_REQUEST", {message: "User not found"}).
	ErrUserNotFoundBadRequest = errors.New("BAD_REQUEST", "User not found", http.StatusBadRequest)

	// Team Errors
	ErrTeamNotFound              = errors.New(TeamNotFound, "Team not found", http.StatusBadRequest)
	ErrTeamsDisabled             = errors.New(TeamsDisabled, "Teams are not enabled", http.StatusNotFound)
	ErrMaximumTeamsReached       = errors.New(MaximumTeamsReached, "You have reached the maximum number of teams", http.StatusBadRequest)
	ErrMaximumTeamMembersReached = errors.New(MaximumTeamMembersReached, "Team member limit reached", http.StatusForbidden)
	ErrCannotRemoveAllTeams      = errors.New(CannotRemoveAllTeams, "Unable to remove last team", http.StatusBadRequest)
	ErrAlreadyTeamMember         = errors.New(AlreadyTeamMember, "User is already a member of this team", http.StatusBadRequest)
	ErrTeamMemberNotFound        = errors.New(TeamMemberNotFound, "User is not a member of the team", http.StatusBadRequest)
	// ErrUserNotMemberOfTeam403 is set-active-team's USER_IS_NOT_A_MEMBER_OF_THE_TEAM (403).
	ErrUserNotMemberOfTeam403 = errors.New(TeamMemberNotFound, "User is not a member of the team", http.StatusForbidden)
	ErrNoActiveTeam           = errors.New("YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM", "You do not have an active team", http.StatusBadRequest)

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
