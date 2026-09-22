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
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrCreateOrg, OrgPermissionsMap[OrCreateOrg].AllowedRoles)},
	}, h.CreateOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrGetOrg.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/get-full-organization",
		Summary:     "Get Organization Details",
		Description: "Fetches details for an organization.",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrGetOrg, OrgPermissionsMap[OrGetOrg].AllowedRoles)},
	}, h.GetOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrUpdateOrg.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/update",
		Summary:     "Update Organization",
		Description: "Updates metadata and fields for an organization (admin/owner required).",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrUpdateOrg, OrgPermissionsMap[OrUpdateOrg].AllowedRoles)},
	}, h.UpdateOrg)
	huma.Register(api, huma.Operation{
		OperationID:   OrDeleteOrg.Str(),
		Method:        http.MethodDelete,
		Path:          path + "/organization/delete",
		Summary:       "Delete Organization",
		Description:   "Deletes an organization and all its memberships.",
		Tags:          orgTags,
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrDeleteOrg, OrgPermissionsMap[OrDeleteOrg].AllowedRoles)},
	}, h.DeleteOrg)
	huma.Register(api, huma.Operation{
		OperationID: OrListOrgs.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/list",
		Summary:     "List User Organizations",
		Description: "Lists all organizations where the authenticated user is a member.",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrListOrgs, OrgPermissionsMap[OrListOrgs].AllowedRoles)},
	}, h.ListOrgs)
	huma.Register(api, huma.Operation{
		OperationID: OrSetActiveOrg.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/set-active",
		Summary:     "Set Active Organization",
		Description: "Marks an organization as active for the current session.",
		Tags:        orgTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrSetActiveOrg, OrgPermissionsMap[OrSetActiveOrg].AllowedRoles)},
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
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrInviteMember, OrgPermissionsMap[OrInviteMember].AllowedRoles)},
	}, h.InviteMember)
	huma.Register(api, huma.Operation{
		OperationID: OrGetInvitation.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/get-invitation",
		Summary:     "Get Invitation Details",
		Description: "Fetches details of a specific invitation.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrGetInvitation, OrgPermissionsMap[OrGetInvitation].AllowedRoles)},
	}, h.GetInvitation)
	huma.Register(api, huma.Operation{
		OperationID: OrAcceptInvitation.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/accept-invitation",
		Summary:     "Accept Invitation",
		Description: "Accepts an invitation to join an organization.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrAcceptInvitation, OrgPermissionsMap[OrAcceptInvitation].AllowedRoles)},
	}, h.AcceptInvitation)
	huma.Register(api, huma.Operation{
		OperationID: OrRejectInvitation.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/reject-invitation",
		Summary:     "Reject Invitation",
		Description: "Rejects an organization invitation.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrRejectInvitation, OrgPermissionsMap[OrRejectInvitation].AllowedRoles)},
	}, h.RejectInvitation)
	huma.Register(api, huma.Operation{
		OperationID: OrCancelInvitation.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/cancel-invitation",
		Summary:     "Cancel Invitation",
		Description: "Cancels a pending invitation.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrCancelInvitation, OrgPermissionsMap[OrCancelInvitation].AllowedRoles)},
	}, h.CancelInvitation)
	huma.Register(api, huma.Operation{
		OperationID: OrListInvitations.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/list-invitations",
		Summary:     "List Organization Invitations",
		Description: "Lists all pending and processed invitations for an organization.",
		Tags:        invitationTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrListInvitations, OrgPermissionsMap[OrListInvitations].AllowedRoles)},
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
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrGetMember, OrgPermissionsMap[OrGetMember].AllowedRoles)},
	}, h.GetMember)
	huma.Register(api, huma.Operation{
		OperationID: OrListMembers.Str(),
		Method:      http.MethodGet,
		Path:        path + "/organization/list-members",
		Summary:     "List Organization Members",
		Description: "Returns a list of members in the organization.",
		Tags:        memberTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrListMembers, OrgPermissionsMap[OrListMembers].AllowedRoles)},
	}, h.ListMembers)
	huma.Register(api, huma.Operation{
		OperationID: OrUpdateMemberRole.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/update-member-role",
		Summary:     "Update Member Role",
		Description: "Changes an organization member's role (owner required).",
		Tags:        memberTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrUpdateMemberRole, OrgPermissionsMap[OrUpdateMemberRole].AllowedRoles)},
	}, h.UpdateMemberRole)
	huma.Register(api, huma.Operation{
		OperationID: OrRemoveMember.Str(),
		Method:      http.MethodPost,
		Path:        path + "/organization/remove-member",
		Summary:     "Remove Member",
		Description: "Removes a member from the organization.",
		Tags:        memberTags,
		Middlewares: huma.Middlewares{h.MiddleWare.Authenticate(), h.MiddleWare.AuthorizeOrg(OrRemoveMember, OrgPermissionsMap[OrRemoveMember].AllowedRoles)},
	}, h.RemoveMember)
}
