package humaorg

import (
	"context"
	"net/http"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgerrors "github.com/better-go-auth/goauth/src/plugins/org/org-errors"
	"github.com/danielgtaylor/huma/v2"
)

// ─── Team Handlers Inputs & Outputs ──────────────────────────────────────────

type CreateTeamInput struct {
	humatypes.AuthHeaders
	Body dtos.CreateTeamInput
}

type UpdateTeamInput struct {
	humatypes.AuthHeaders
	Body dtos.UpdateTeamInput
}

type DeleteTeamInput struct {
	humatypes.AuthHeaders
	Body dtos.DeleteTeamInput
}

type ListTeamsInput struct {
	humatypes.AuthHeaders
	OrganizationID string `query:"organizationId"`
}

type AddTeamMemberInput struct {
	humatypes.AuthHeaders
	Body dtos.AddTeamMemberInput
}

type RemoveTeamMemberInput struct {
	humatypes.AuthHeaders
	Body dtos.RemoveTeamMemberInput
}

type SetActiveTeamInput struct {
	humatypes.AuthHeaders
	Body dtos.SetActiveTeamInput
}

type TeamOutput struct {
	Body dtos.TeamResponse
}

type ListTeamsOutput struct {
	Body []dtos.TeamResponse
}

type TeamMemberOutput struct {
	Body dtos.TeamMemberResponse
}

type ListTeamMembersOutput struct {
	Body []dtos.TeamMemberResponse
}

// SetActiveTeamOutput is the active team, or null.
type SetActiveTeamOutput struct {
	Body *dtos.TeamResponse
}

// ─── Team Handlers ────────────────────────────────────────────────────────────

func (h *OrgHandler) CreateTeam(ctx context.Context, in *CreateTeamInput) (*TeamOutput, error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, orgID, err := h.RequireOrgOp(ctx, in.AuthHeaders, in.Body.OrganizationID, OrCreateTeam)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	in.Body.OrganizationID = orgID
	team, err := h.Org.CreateTeam(ctx, in.Body, sessionResp.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return &TeamOutput{Body: *dtos.TeamToResponse(team)}, nil
}

func (h *OrgHandler) UpdateTeam(ctx context.Context, in *UpdateTeamInput) (*TeamOutput, error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, orgID, err := h.RequireOrgOp(ctx, in.AuthHeaders, in.Body.OrganizationID, OrUpdateTeam)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	in.Body.OrganizationID = orgID
	if in.Body.Data != nil && in.Body.Name == "" {
		in.Body.Name = in.Body.Data.Name
	}
	team, err := h.Org.UpdateTeam(ctx, in.Body, sessionResp.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return &TeamOutput{Body: *dtos.TeamToResponse(team)}, nil
}

// DeleteTeam is better-auth's POST /organization/remove-team: {message: "Team removed successfully."}.
func (h *OrgHandler) DeleteTeam(ctx context.Context, in *DeleteTeamInput) (*humatypes.HumaRes[dtos.MessageResponse], error) {
	// Step 1: Ensure teams feature is enabled
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	// Step 2: membership and team:delete permission
	sessionResp, orgID, err := h.RequireOrgOp(ctx, in.AuthHeaders, in.Body.OrganizationID, OrDeleteTeam)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	in.Body.OrganizationID = orgID
	// Step 3: better-auth refuses to delete the caller's active team, and teams of other organizations
	if sessionResp.Session.ActiveTeamID != nil && *sessionResp.Session.ActiveTeamID == in.Body.TeamID {
		return nil, humatypes.RespondErr(orgerrors.ErrNotAllowedToDeleteThisTeam)
	}
	if team, tErr := h.Org.GetTeam(ctx, in.Body.TeamID, sessionResp.User.ID); tErr != nil || team == nil || team.OrganizationID != orgID {
		return nil, humatypes.RespondErr(orgerrors.ErrTeamNotFound)
	}
	// Step 4: delete
	if err := h.Org.DeleteTeam(ctx, in.Body, sessionResp.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(dtos.MessageResponse{Message: "Team removed successfully."}, http.StatusOK), nil
}

// ListUserTeams is better-auth's GET /organization/list-user-teams: every team the caller belongs to, in
// organizations they are still a member of.
func (h *OrgHandler) ListUserTeams(ctx context.Context, in *ListUserTeamsInput) (*ListTeamsOutput, error) {
	// Step 1: Ensure teams feature is enabled
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	// Step 2: Authenticate requesting user
	sessionResp, err := h.Authenticate(ctx, in.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	// Step 3: the user's teams
	teams, err := h.Org.ListUserTeams(ctx, sessionResp.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	out := make([]dtos.TeamResponse, len(teams))
	for i := range teams {
		out[i] = *dtos.TeamToResponse(&teams[i])
	}
	return &ListTeamsOutput{Body: out}, nil
}

func (h *OrgHandler) ListTeams(ctx context.Context, in *ListTeamsInput) (*ListTeamsOutput, error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, orgID, err := h.requireMember(ctx, in.AuthHeaders, in.OrganizationID, errorsFor(OrListTeams))
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	teams, _, err := h.Org.ListTeams(ctx, orgID, sessionResp.User.ID, models.Pagination{})
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	out := make([]dtos.TeamResponse, len(teams))
	for i := range teams {
		out[i] = *dtos.TeamToResponse(&teams[i])
	}
	return &ListTeamsOutput{Body: out}, nil
}

func (h *OrgHandler) AddTeamMember(ctx context.Context, in *AddTeamMemberInput) (*TeamMemberOutput, error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, orgID, err := h.RequireOrgOp(ctx, in.AuthHeaders, in.Body.OrganizationID, OrAddTeamMember)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	in.Body.OrganizationID = orgID
	member, err := h.Org.AddTeamMember(ctx, in.Body, sessionResp.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return &TeamMemberOutput{Body: *dtos.TeamMemberToResponse(member)}, nil
}

// RemoveTeamMember is better-auth's POST /organization/remove-team-member: {message: "Team member removed successfully."}.
func (h *OrgHandler) RemoveTeamMember(ctx context.Context, in *RemoveTeamMemberInput) (*humatypes.HumaRes[dtos.MessageResponse], error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, orgID, err := h.RequireOrgOp(ctx, in.AuthHeaders, in.Body.OrganizationID, OrRemoveTeamMember)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	in.Body.OrganizationID = orgID
	if err := h.Org.RemoveTeamMember(ctx, in.Body, sessionResp.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.MakeRes(dtos.MessageResponse{Message: "Team member removed successfully."}, http.StatusOK), nil
}

// SetActiveTeam is better-auth's POST /organization/set-active-team: the now active team (of the active
// organization), or null when teamId is null (or omitted with no active team).
func (h *OrgHandler) SetActiveTeam(ctx context.Context, in *SetActiveTeamInput) (*SetActiveTeamOutput, error) {
	// Step 1: Ensure teams feature is enabled and authenticate
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, err := h.Authenticate(ctx, in.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	active := sessionResp.Session.ActiveTeamID
	// Step 2: teamId: null unsets the active team
	if in.Body.TeamIDNull {
		if active != nil && *active != "" {
			if _, err := h.Org.SetActiveTeam(ctx, sessionResp.Session.ID, nil, sessionResp.User.ID); err != nil {
				return nil, humatypes.RespondErr(err)
			}
		}
		return &SetActiveTeamOutput{}, nil
	}
	// Step 3: an omitted teamId re-selects the active team (none → null)
	teamID := ""
	switch {
	case in.Body.TeamID != nil && *in.Body.TeamID != "":
		teamID = *in.Body.TeamID
	case active != nil && *active != "":
		teamID = *active
	default:
		return &SetActiveTeamOutput{}, nil
	}
	// Step 4: the team must belong to the active organization
	if sessionResp.Session.ActiveOrganizationID == nil || *sessionResp.Session.ActiveOrganizationID == "" {
		return nil, humatypes.RespondErr(orgerrors.ErrNoActiveOrganization)
	}
	team, err := h.Org.GetTeam(ctx, teamID, sessionResp.User.ID)
	if err != nil || team == nil || team.OrganizationID != *sessionResp.Session.ActiveOrganizationID {
		return nil, humatypes.RespondErr(orgerrors.ErrTeamNotFound)
	}
	// Step 5: activate (the service checks team membership: 403 USER_IS_NOT_A_MEMBER_OF_THE_TEAM)
	if _, err := h.Org.SetActiveTeam(ctx, sessionResp.Session.ID, &teamID, sessionResp.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return &SetActiveTeamOutput{Body: dtos.TeamToResponse(team)}, nil
}

type ListTeamMembersInput struct {
	humatypes.AuthHeaders
	TeamID string `query:"teamId,omitempty" doc:"Team ID (defaults to session active team)"`
}

// ListTeamMembers returns all members of a team, including preloaded user details.
func (h *OrgHandler) ListTeamMembers(ctx context.Context, in *ListTeamMembersInput) (*ListTeamMembersOutput, error) {
	// Step 1: Ensure teams feature is enabled
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}

	// Step 2: Authenticate requesting user
	sessionResp, err := h.Authenticate(ctx, in.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}

	// Step 3: Resolve target team ID from query parameter or active session team
	teamID := in.TeamID
	if teamID == "" && sessionResp.Session.ActiveTeamID != nil {
		teamID = *sessionResp.Session.ActiveTeamID
	}
	if teamID == "" {
		return nil, humatypes.RespondErr(orgerrors.ErrNoActiveTeam)
	}

	// Step 4: Fetch team members via service layer (the caller must be in the organization and the team)
	members, _, err := h.Org.ListTeamMembers(ctx, teamID, sessionResp.User.ID, defaultPagi())
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}

	// Step 5: Map members to response DTOs
	resps := make([]dtos.TeamMemberResponse, 0, len(members))
	for i := range members {
		resps = append(resps, *dtos.TeamMemberToResponse(&members[i]))
	}
	return &ListTeamMembersOutput{Body: resps}, nil
}
