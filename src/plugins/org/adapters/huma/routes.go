package humaorg

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/models"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
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
	OrInviteMember     = consts.OperationId("Or-7-InviteMember")
	OrGetInvitation    = consts.OperationId("Or-8-GetInvitation")
	OrAcceptInvitation = consts.OperationId("Or-9-AcceptInvitation")
	OrRejectInvitation = consts.OperationId("Or-10-RejectInvitation")
	OrCancelInvitation = consts.OperationId("Or-11-CancelInvitation")
	OrListInvitations  = consts.OperationId("Or-12-ListInvitations")

	// Member
	OrGetMember        = consts.OperationId("Or-13-GetMember")
	OrListMembers      = consts.OperationId("Or-14-ListMembers")
	OrUpdateMemberRole = consts.OperationId("Or-15-UpdateMemberRole")
	OrRemoveMember     = consts.OperationId("Or-16-RemoveMember")

	// Teams
	OrCreateTeam       = consts.OperationId("Or-17-CreateTeam")
	OrUpdateTeam       = consts.OperationId("Or-18-UpdateTeam")
	OrDeleteTeam       = consts.OperationId("Or-19-DeleteTeam")
	OrListTeams        = consts.OperationId("Or-20-ListTeams")
	OrAddTeamMember    = consts.OperationId("Or-21-AddTeamMember")
	OrRemoveTeamMember = consts.OperationId("Or-22-RemoveTeamMember")
	OrSetActiveTeam    = consts.OperationId("Or-23-SetActiveTeam")

	// Admin
	OrAdminApproveOrg = consts.OperationId("Or-Admin-1-ApproveOrg")
	OrAdminBlockOrg   = consts.OperationId("Or-Admin-2-BlockOrg")
	OrAdminUnblockOrg = consts.OperationId("Or-Admin-3-UnblockOrg")
	OrAdminListOrgs   = consts.OperationId("Or-Admin-4-ListOrgs")
)

var OrgPermissionsMap = map[consts.OperationId]models.OperationAccessDto{
	// Org
	OrCreateOrg:    {AllowedRoles: []string{}, Description: "Creating An Organization"},
	OrGetOrg:       {AllowedRoles: []string{}, Description: "Get Organization Details"},
	OrUpdateOrg:    {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "Update Organization"},
	OrDeleteOrg:    {AllowedRoles: []string{orgmodels.OrgRoleOwner.String()}, Description: "Delete Organization"},
	OrListOrgs:     {AllowedRoles: []string{}, Description: "List User Organizations"},
	OrSetActiveOrg: {AllowedRoles: []string{}, Description: "Set Active Organization"},

	// Invitation
	OrInviteMember:     {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "Invite Member"},
	OrGetInvitation:    {AllowedRoles: []string{}, Description: "Get Invitation Details"},
	OrAcceptInvitation: {AllowedRoles: []string{}, Description: "Accept Invitation"},
	OrRejectInvitation: {AllowedRoles: []string{}, Description: "Reject Invitation"},
	OrCancelInvitation: {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "Cancel Invitation"},
	OrListInvitations:  {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "List Organization Invitations"},

	// Member
	OrGetMember:        {AllowedRoles: []string{}, Description: "Get Member Details"},
	OrListMembers:      {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "List Organization Members"},
	OrUpdateMemberRole: {AllowedRoles: []string{orgmodels.OrgRoleOwner.String()}, Description: "Update Member Role"},
	OrRemoveMember:     {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "Remove Member"},

	// Teams
	OrCreateTeam:       {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "Create Team"},
	OrUpdateTeam:       {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "Update Team"},
	OrDeleteTeam:       {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "Delete Team"},
	OrListTeams:        {AllowedRoles: []string{}, Description: "List Teams"},
	OrAddTeamMember:    {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "Add Team Member"},
	OrRemoveTeamMember: {AllowedRoles: []string{orgmodels.OrgRoleOwner.String(), orgmodels.OrgRoleAdmin.String()}, Description: "Remove Team Member"},
	OrSetActiveTeam:    {AllowedRoles: []string{}, Description: "Set Active Team"},

	// Admin (system-level Admin role required — enforced in handler, not middleware)
	OrAdminApproveOrg: {AllowedRoles: []string{}, Description: "Approve Pending Organization"},
	OrAdminBlockOrg:   {AllowedRoles: []string{}, Description: "Block/Suspend Organization"},
	OrAdminUnblockOrg: {AllowedRoles: []string{}, Description: "Unblock/Re-activate Organization"},
	OrAdminListOrgs:   {AllowedRoles: []string{}, Description: "Admin: List All Organizations"},
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

	adminTags := []string{"Admin-Orgs"}
	// Admin Org Management
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
}
