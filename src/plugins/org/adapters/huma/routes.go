package humaorg

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/models"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/danielgtaylor/huma/v2"
)

const (
	// Org
	OrCreateOrg    = consts.OperationId("Or-1-CreateOrg")
	OrGetOrg       = consts.OperationId("Or-2-GetOrg")
	OrUpdateOrg    = consts.OperationId("Or-3-UpdateOrg")
	OrDeleteOrg    = consts.OperationId("Or-4-DeleteOrg")
	OrListOrgs     = consts.OperationId("Or-5-ListOrgs")
	OrSetActiveOrg = consts.OperationId("Or-6-SetActiveOrg")

	// Invitation
	OrInviteMember        = consts.OperationId("Or-7-InviteMember")
	OrGetInvitation       = consts.OperationId("Or-8-GetInvitation")
	OrAcceptInvitation    = consts.OperationId("Or-9-AcceptInvitation")
	OrRejectInvitation    = consts.OperationId("Or-10-RejectInvitation")
	OrCancelInvitation    = consts.OperationId("Or-11-CancelInvitation")
	OrListInvitations     = consts.OperationId("Or-12-ListInvitations")
	OrListUserInvitations = consts.OperationId("Or-12b-ListUserInvitations")

	// Member
	OrGetMember        = consts.OperationId("Or-13-GetMember")
	OrListMembers      = consts.OperationId("Or-14-ListMembers")
	OrUpdateMemberRole = consts.OperationId("Or-15-UpdateMemberRole")
	OrRemoveMember     = consts.OperationId("Or-16-RemoveMember")
	OrLeaveOrg         = consts.OperationId("Or-16b-LeaveOrg")

	// Teams
	OrCreateTeam       = consts.OperationId("Or-17-CreateTeam")
	OrUpdateTeam       = consts.OperationId("Or-18-UpdateTeam")
	OrDeleteTeam       = consts.OperationId("Or-19-DeleteTeam")
	OrListTeams        = consts.OperationId("Or-20-ListTeams")
	OrAddTeamMember    = consts.OperationId("Or-21-AddTeamMember")
	OrRemoveTeamMember = consts.OperationId("Or-22-RemoveTeamMember")
	OrSetActiveTeam    = consts.OperationId("Or-23-SetActiveTeam")
	OrListTeamMembers  = consts.OperationId("Or-24-ListTeamMembers")

	// Admin
	OrAdminCreateOrg  = consts.OperationId("Or-Admin-0-CreateOrg")
	OrAdminApproveOrg = consts.OperationId("Or-Admin-1-ApproveOrg")
	OrAdminBlockOrg   = consts.OperationId("Or-Admin-2-BlockOrg")
	OrAdminUnblockOrg = consts.OperationId("Or-Admin-3-UnblockOrg")
	OrAdminListOrgs   = consts.OperationId("Or-Admin-4-ListOrgs")
	OrAdminGetOrg     = consts.OperationId("Or-Admin-5-GetOrg")

	// Access control (better-auth /organization/has-permission and dynamic role CRUD)
	OrHasPermission = consts.OperationId("Or-25-HasPermission")
	OrCreateRole    = consts.OperationId("Or-26-CreateRole")
	OrDeleteRole    = consts.OperationId("Or-27-DeleteRole")
	OrListRoles     = consts.OperationId("Or-28-ListRoles")
	OrGetRole       = consts.OperationId("Or-29-GetRole")
	OrUpdateRole    = consts.OperationId("Or-30-UpdateRole")
)

var OrgPermissionsMap = map[consts.OperationId]models.OperationAccessDto{
	// Org
	OrCreateOrg:    {AllowedRoles: []string{}, Description: "Creating An Organization"},
	OrGetOrg:       {AllowedRoles: []string{}, Description: "Get Organization Details"},
	OrUpdateOrg:    {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "Update Organization"},
	OrDeleteOrg:    {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str()}, Description: "Delete Organization"},
	OrListOrgs:     {AllowedRoles: []string{}, Description: "List User Organizations"},
	OrSetActiveOrg: {AllowedRoles: []string{}, Description: "Set Active Organization"},

	// Invitation
	OrInviteMember:        {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "Invite Member"},
	OrGetInvitation:       {AllowedRoles: []string{}, Description: "Get Invitation Details"},
	OrAcceptInvitation:    {AllowedRoles: []string{}, Description: "Accept Invitation"},
	OrRejectInvitation:    {AllowedRoles: []string{}, Description: "Reject Invitation"},
	OrCancelInvitation:    {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "Cancel Invitation"},
	OrListInvitations:     {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "List Organization Invitations"},
	OrListUserInvitations: {AllowedRoles: []string{}, Description: "List User Invitations"},

	// Member
	OrGetMember:        {AllowedRoles: []string{}, Description: "Get Member Details"},
	OrListMembers:      {AllowedRoles: []string{}, Description: "List Organization Members"},
	OrUpdateMemberRole: {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str()}, Description: "Update Member Role"},
	OrRemoveMember:     {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "Remove Member"},
	OrLeaveOrg:         {AllowedRoles: []string{}, Description: "Leave Organization"},

	// Teams
	OrCreateTeam:       {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "Create Team"},
	OrUpdateTeam:       {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "Update Team"},
	OrDeleteTeam:       {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "Delete Team"},
	OrListTeams:        {AllowedRoles: []string{}, Description: "List Teams"},
	OrAddTeamMember:    {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "Add Team Member"},
	OrRemoveTeamMember: {AllowedRoles: []string{orgmodels.OrgRoleOwner.Str(), orgmodels.OrgRoleAdmin.Str()}, Description: "Remove Team Member"},
	OrSetActiveTeam:    {AllowedRoles: []string{}, Description: "Set Active Team"},
	OrListTeamMembers:  {AllowedRoles: []string{}, Description: "List Team Members"},

	// Admin (system-level Admin role required — enforced in handler, not middleware)
	OrAdminCreateOrg:  {AllowedRoles: []string{}, Description: "Admin: Create Organization"},
	OrAdminApproveOrg: {AllowedRoles: []string{}, Description: "Approve Pending Organization"},
	OrAdminBlockOrg:   {AllowedRoles: []string{}, Description: "Block/Suspend Organization"},
	OrAdminUnblockOrg: {AllowedRoles: []string{}, Description: "Unblock/Re-activate Organization"},
	OrAdminListOrgs:   {AllowedRoles: []string{}, Description: "Admin: List All Organizations"},
	OrAdminGetOrg:     {AllowedRoles: []string{}, Description: "Admin: Get Organization"},

	// Access control (permission checks done in the service: ac:create/read/update/delete)
	OrHasPermission: {AllowedRoles: []string{}, Description: "Check Organization Permission"},
	OrCreateRole:    {AllowedRoles: []string{}, Description: "Create Organization Role"},
	OrDeleteRole:    {AllowedRoles: []string{}, Description: "Delete Organization Role"},
	OrListRoles:     {AllowedRoles: []string{}, Description: "List Organization Roles"},
	OrGetRole:       {AllowedRoles: []string{}, Description: "Get Organization Role"},
	OrUpdateRole:    {AllowedRoles: []string{}, Description: "Update Organization Role"},
}

// OrgRoutePermissions maps operations to the better-auth permission the equivalent better-auth
// endpoint checks (plugins/organization/routes/*). See OrgHandler.RequireOrgOp for how it combines
// with OrgPermissionsMap.
var OrgRoutePermissions = map[consts.OperationId]access.Request{
	OrUpdateOrg:        access.Req(map[string][]string{"organization": {"update"}}),
	OrDeleteOrg:        access.Req(map[string][]string{"organization": {"delete"}}),
	OrInviteMember:     access.Req(map[string][]string{"invitation": {"create"}}),
	OrCancelInvitation: access.Req(map[string][]string{"invitation": {"cancel"}}),
	OrUpdateMemberRole: access.Req(map[string][]string{"member": {"update"}}),
	OrRemoveMember:     access.Req(map[string][]string{"member": {"delete"}}),
	OrCreateTeam:       access.Req(map[string][]string{"team": {"create"}}),
	OrUpdateTeam:       access.Req(map[string][]string{"team": {"update"}}),
	OrDeleteTeam:       access.Req(map[string][]string{"team": {"delete"}}),
	OrAddTeamMember:    access.Req(map[string][]string{"member": {"update"}}),
	OrRemoveTeamMember: access.Req(map[string][]string{"member": {"delete"}}),
}

// SetupOrgRoutes registers all organization, invitation, and member endpoints.
func SetupOrgRoutes(api huma.API, h *OrgHandler) {
	path := h.Cfg.BasePath
	orgTags := []string{"Organizations"}

	// Org
	huma.Register(api, huma.Operation{
		OperationID: OrCreateOrg.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/create",
		Summary:     "Create Organization",
		Description: "Creates a new organization and registers the creator as its owner.",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.CreateOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrGetOrg.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/get-full-organization",
		Summary:     "Get Organization Details",
		Description: "Fetches details for an organization.",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.GetOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrUpdateOrg.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/update",
		Summary:     "Update Organization",
		Description: "Updates metadata and fields for an organization (admin/owner required).",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.UpdateOrg)
	huma.Register(api, huma.Operation{
		OperationID:   OrDeleteOrg.Str(),
		Method:        http.MethodDelete,
		Path:          path + "/organization/delete",
		Summary:       "Delete Organization",
		Description:   "Deletes an organization and all its memberships.",
		Tags:          orgTags,
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.DeleteOrg)
	huma.Register(api, huma.Operation{
		OperationID:   OrDeleteOrg.Str() + "-Post",
		Method:        http.MethodPost,
		Path:          path + "/organization/delete",
		Summary:       "Delete Organization (Better Auth POST alias)",
		Description:   "Deletes an organization and all its memberships.",
		Tags:          orgTags,
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.DeleteOrg)
	huma.Register(api, huma.Operation{
		OperationID: "Or-CheckSlug",
		Method:      http.MethodPost,
		Path:        path + "/organization/check-slug",
		Summary:     "Check Organization Slug",
		Description: "Checks whether an organization slug is available.",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.CheckSlug)
	huma.Register(api, huma.Operation{
		OperationID: OrListOrgs.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/list",
		Summary:     "List User Organizations",
		Description: "Lists all organizations where the authenticated user is a member.",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListOrgs)
	huma.Register(api, huma.Operation{
		OperationID: OrSetActiveOrg.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/set-active",
		Summary:     "Set Active Organization",
		Description: "Marks an organization as active for the current session.",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.SetActiveOrg)

	invitationTags := []string{"Org-Invitation"}
	// Invitation
	huma.Register(api, huma.Operation{
		OperationID: OrInviteMember.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/invite-member",
		Summary:     "Invite Member",
		Description: "Sends an organization invitation to an email address.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.InviteMember)
	huma.Register(api, huma.Operation{
		OperationID: OrGetInvitation.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/get-invitation",
		Summary:     "Get Invitation Details",
		Description: "Fetches details of a specific invitation.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.GetInvitation)
	huma.Register(api, huma.Operation{
		OperationID: OrAcceptInvitation.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/accept-invitation",
		Summary:     "Accept Invitation",
		Description: "Accepts an invitation to join an organization.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.AcceptInvitation)
	huma.Register(api, huma.Operation{
		OperationID: OrRejectInvitation.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/reject-invitation",
		Summary:     "Reject Invitation",
		Description: "Rejects an organization invitation.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.RejectInvitation)
	huma.Register(api, huma.Operation{
		OperationID: OrCancelInvitation.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/cancel-invitation",
		Summary:     "Cancel Invitation",
		Description: "Cancels a pending invitation.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.CancelInvitation)
	huma.Register(api, huma.Operation{
		OperationID: OrListInvitations.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/list-invitations",
		Summary:     "List Organization Invitations",
		Description: "Lists all pending and processed invitations for an organization.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListInvitations)
	huma.Register(api, huma.Operation{
		OperationID: OrListUserInvitations.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/list-user-invitations",
		Summary:     "List User Invitations",
		Description: "Lists pending invitations addressed to the authenticated user's email.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListUserInvitations)

	memberTags := []string{"Org-Members"}
	// Member
	huma.Register(api, huma.Operation{
		OperationID: OrGetMember.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/get-member",
		Summary:     "Get Member Details",
		Description: "Returns details of an organization member.",
		Tags:        memberTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.GetMember)
	huma.Register(api, huma.Operation{
		OperationID: OrListMembers.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/list-members",
		Summary:     "List Organization Members",
		Description: "Returns a list of members in the organization.",
		Tags:        memberTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListMembers)
	huma.Register(api, huma.Operation{
		OperationID: OrUpdateMemberRole.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/update-member-role",
		Summary:     "Update Member Role",
		Description: "Changes an organization member's role (owner required).",
		Tags:        memberTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.UpdateMemberRole)
	huma.Register(api, huma.Operation{
		OperationID: OrRemoveMember.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/remove-member",
		Summary:     "Remove Member",
		Description: "Removes a member from the organization.",
		Tags:        memberTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.RemoveMember)
	huma.Register(api, huma.Operation{
		OperationID: OrLeaveOrg.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/leave",
		Summary:     "Leave Organization",
		Description: "Allows the authenticated member to voluntarily leave an organization.",
		Tags:        memberTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.LeaveOrganization)

	teamTags := []string{"Teams"}
	huma.Register(api, huma.Operation{
		OperationID: OrCreateTeam.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/team/create",
		Summary:     "Create Team",
		Description: "Creates a new team within an organization.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.CreateTeam)
	huma.Register(api, huma.Operation{
		OperationID: OrUpdateTeam.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/team/update",
		Summary:     "Update Team",
		Description: "Updates an existing team's details.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.UpdateTeam)
	huma.Register(api, huma.Operation{
		OperationID: OrDeleteTeam.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/team/delete",
		Summary:     "Delete Team",
		Description: "Deletes a team from an organization.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.DeleteTeam)
	huma.Register(api, huma.Operation{
		OperationID: OrListTeams.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/team/list",
		Summary:     "List Teams",
		Description: "Returns all teams within an organization.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListTeams)
	huma.Register(api, huma.Operation{
		OperationID: OrAddTeamMember.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/team/add-member",
		Summary:     "Add Team Member",
		Description: "Adds an existing organization member to a team.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.AddTeamMember)
	huma.Register(api, huma.Operation{
		OperationID: OrRemoveTeamMember.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/team/remove-member",
		Summary:     "Remove Team Member",
		Description: "Removes a member from a team.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.RemoveTeamMember)
	huma.Register(api, huma.Operation{
		OperationID: OrSetActiveTeam.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/set-active-team",
		Summary:     "Set Active Team",
		Description: "Sets or unsets the active team for the session.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.SetActiveTeam)
	huma.Register(api, huma.Operation{
		OperationID: OrListTeamMembers.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/team/list-members",
		Summary:     "List Team Members",
		Description: "Returns all members of a team with user details.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListTeamMembers)

	// Better Auth canonical team route aliases (/organization/*-team)
	huma.Register(api, huma.Operation{
		OperationID: OrCreateTeam.Str() + "-BA",
		Method:      http.MethodPost,
		Path:        path + "/organization/create-team",
		Summary:     "Create Team (Better Auth)",
		Description: "Creates a new team within an organization.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.CreateTeam)
	huma.Register(api, huma.Operation{
		OperationID: OrUpdateTeam.Str() + "-BA",
		Method:      http.MethodPost,
		Path:        path + "/organization/update-team",
		Summary:     "Update Team (Better Auth)",
		Description: "Updates an existing team's details.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.UpdateTeam)
	huma.Register(api, huma.Operation{
		OperationID: OrDeleteTeam.Str() + "-BA",
		Method:      http.MethodPost,
		Path:        path + "/organization/remove-team",
		Summary:     "Remove Team (Better Auth)",
		Description: "Deletes a team from an organization.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.DeleteTeam)
	huma.Register(api, huma.Operation{
		OperationID: OrListTeams.Str() + "-BA",
		Method:      http.MethodGet,
		Path:        path + "/organization/list-teams",
		Summary:     "List Teams (Better Auth)",
		Description: "Returns all teams within an organization.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListTeams)
	huma.Register(api, huma.Operation{
		OperationID: OrAddTeamMember.Str() + "-BA",
		Method:      http.MethodPost,
		Path:        path + "/organization/add-team-member",
		Summary:     "Add Team Member (Better Auth)",
		Description: "Adds an existing organization member to a team.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.AddTeamMember)
	huma.Register(api, huma.Operation{
		OperationID: OrRemoveTeamMember.Str() + "-BA",
		Method:      http.MethodPost,
		Path:        path + "/organization/remove-team-member",
		Summary:     "Remove Team Member (Better Auth)",
		Description: "Removes a member from a team.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.RemoveTeamMember)
	huma.Register(api, huma.Operation{
		OperationID: OrListTeamMembers.Str() + "-BA",
		Method:      http.MethodGet,
		Path:        path + "/organization/list-team-members",
		Summary:     "List Team Members (Better Auth)",
		Description: "Returns all members of a team with user details.",
		Tags:        teamTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.ListTeamMembers)

	adminTags := []string{"Admin-Orgs"}
	// Admin Org Management
	huma.Register(api, huma.Operation{
		OperationID:   OrAdminCreateOrg.Str(),
		Method:        http.MethodPost,
		Path:          path + "/admin/organization/create",
		Summary:       "[Admin] Create Organization",
		Description:   "Creates an active organization immediately, optionally assigning an ownerUserId. Requires system Admin role.",
		Tags:          adminTags,
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.AdminCreateOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrAdminGetOrg.Str(),
		Method:      http.MethodGet,
		Path:        path + "/admin/organization/get",
		Summary:     "[Admin] Get Organization",
		Description: "Returns organization details by organizationId. Requires system Admin role.",
		Tags:        adminTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.AdminGetOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrAdminApproveOrg.Str(),
		Method:      http.MethodPost,
		Path:        path + "/admin/organization/approve",
		Summary:     "[Admin] Approve Organization",
		Description: "Approves a pending organization, setting its status to active. Requires system Admin role.",
		Tags:        adminTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.AdminApproveOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrAdminBlockOrg.Str(),
		Method:      http.MethodPost,
		Path:        path + "/admin/organization/block",
		Summary:     "[Admin] Block Organization",
		Description: "Suspends an organization. Requires system Admin role.",
		Tags:        adminTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.AdminBlockOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrAdminUnblockOrg.Str(),
		Method:      http.MethodPost,
		Path:        path + "/admin/organization/unblock",
		Summary:     "[Admin] Unblock Organization",
		Description: "Re-activates a suspended or inactive organization. Requires system Admin role.",
		Tags:        adminTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.AdminUnblockOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrAdminListOrgs.Str(),
		Method:      http.MethodGet,
		Path:        path + "/admin/organization/list",
		Summary:     "[Admin] List All Organizations",
		Description: "Returns all organizations with optional status filter. Requires system Admin role.",
		Tags:        adminTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate()},
	}, h.AdminListOrgs)

	// Access control
	setupAccessControlRoutes(api, h, path)
}
