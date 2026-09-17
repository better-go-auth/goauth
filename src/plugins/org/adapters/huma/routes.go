package humaorg

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// SetupOrgRoutes registers all organization, invitation, and member endpoints.
func SetupOrgRoutes(api huma.API, h *OrgHandler) {
	path := h.Cfg.BasePath
	orgTags := []string{"Organizations"}

	// Org
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path + "/organization/create", Summary: "Create Organization", Description: "Creates a new organization and registers the creator as its owner.", Tags: orgTags}, h.CreateOrg)
	huma.Register(api, huma.Operation{Method: http.MethodGet, Path: path + "/organization/get-full-organization", Summary: "Get Organization Details", Description: "Fetches details for an organization.", Tags: orgTags}, h.GetOrg)
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path + "/organization/update", Summary: "Update Organization", Description: "Updates metadata and fields for an organization (admin/owner required).", Tags: orgTags}, h.UpdateOrg)
	huma.Register(api, huma.Operation{Method: http.MethodDelete, Path: path + "/organization/delete", Summary: "Delete Organization", Description: "Deletes an organization and all its memberships.", Tags: orgTags}, h.DeleteOrg)
	huma.Register(api, huma.Operation{Method: http.MethodGet, Path: path + "/organization/list", Summary: "List User Organizations", Description: "Lists all organizations where the authenticated user is a member.", Tags: orgTags}, h.ListOrgs)
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path + "/organization/set-active", Summary: "Set Active Organization", Description: "Marks an organization as active for the current session.", Tags: orgTags}, h.SetActiveOrg)

	invitationTags := []string{"Org-Invitation"}
	// Invitation
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path + "/organization/invite-member", Summary: "Invite Member", Description: "Sends an organization invitation to an email address.", Tags: invitationTags}, h.InviteMember)
	huma.Register(api, huma.Operation{Method: http.MethodGet, Path: path + "/organization/get-invitation", Summary: "Get Invitation Details", Description: "Fetches details of a specific invitation.", Tags: invitationTags}, h.GetInvitation)
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path + "/organization/accept-invitation", Summary: "Accept Invitation", Description: "Accepts an invitation to join an organization.", Tags: invitationTags}, h.AcceptInvitation)
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path + "/organization/reject-invitation", Summary: "Reject Invitation", Description: "Rejects an organization invitation.", Tags: invitationTags}, h.RejectInvitation)
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path + "/organization/cancel-invitation", Summary: "Cancel Invitation", Description: "Cancels a pending invitation.", Tags: invitationTags}, h.CancelInvitation)
	huma.Register(api, huma.Operation{Method: http.MethodGet, Path: path + "/organization/list-invitations", Summary: "List Organization Invitations", Description: "Lists all pending and processed invitations for an organization.", Tags: invitationTags}, h.ListInvitations)

	memberTags := []string{"Org-Members"}
	// Member
	huma.Register(api, huma.Operation{Method: http.MethodGet, Path: path + "/organization/get-member", Summary: "Get Member Details", Description: "Returns details of an organization member.", Tags: memberTags}, h.GetMember)
	huma.Register(api, huma.Operation{Method: http.MethodGet, Path: path + "/organization/list-members", Summary: "List Organization Members", Description: "Returns a list of members in the organization.", Tags: memberTags}, h.ListMembers)
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path + "/organization/update-member-role", Summary: "Update Member Role", Description: "Changes an organization member's role (owner required).", Tags: memberTags}, h.UpdateMemberRole)
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path + "/organization/remove-member", Summary: "Remove Member", Description: "Removes a member from the organization.", Tags: memberTags}, h.RemoveMember)
}
