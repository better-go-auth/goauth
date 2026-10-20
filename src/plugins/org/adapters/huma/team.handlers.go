package humaorg

import (
	"context"
	"net/http"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
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

type SetActiveTeamOutput struct {
	Body authdtos.SessionWithUser
}

// ─── Team Handlers ────────────────────────────────────────────────────────────

func (h *OrgHandler) CreateTeam(ctx context.Context, in *CreateTeamInput) (*TeamOutput, error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, _, err := h.RequireOrgMember(ctx, in.AuthHeaders, in.Body.OrganizationID, rolesFor(OrCreateTeam)...)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
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
	sessionResp, _, err := h.RequireOrgMember(ctx, in.AuthHeaders, in.Body.OrganizationID, rolesFor(OrUpdateTeam)...)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	team, err := h.Org.UpdateTeam(ctx, in.Body, sessionResp.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return &TeamOutput{Body: *dtos.TeamToResponse(team)}, nil
}

func (h *OrgHandler) DeleteTeam(ctx context.Context, in *DeleteTeamInput) (*humatypes.SuccessOutput, error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, _, err := h.RequireOrgMember(ctx, in.AuthHeaders, in.Body.OrganizationID, rolesFor(OrDeleteTeam)...)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.DeleteTeam(ctx, in.Body, sessionResp.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

func (h *OrgHandler) ListTeams(ctx context.Context, in *ListTeamsInput) (*ListTeamsOutput, error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, orgID, err := h.RequireOrgMember(ctx, in.AuthHeaders, in.OrganizationID)
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
	sessionResp, _, err := h.RequireOrgMember(ctx, in.AuthHeaders, in.Body.OrganizationID, rolesFor(OrAddTeamMember)...)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	member, err := h.Org.AddTeamMember(ctx, in.Body, sessionResp.User.ID)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return &TeamMemberOutput{Body: *dtos.TeamMemberToResponse(member)}, nil
}

func (h *OrgHandler) RemoveTeamMember(ctx context.Context, in *RemoveTeamMemberInput) (*humatypes.SuccessOutput, error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, _, err := h.RequireOrgMember(ctx, in.AuthHeaders, in.Body.OrganizationID, rolesFor(OrRemoveTeamMember)...)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	if err := h.Org.RemoveTeamMember(ctx, in.Body, sessionResp.User.ID); err != nil {
		return nil, humatypes.RespondErr(err)
	}
	return humatypes.SuccessRes(http.StatusOK), nil
}

func (h *OrgHandler) SetActiveTeam(ctx context.Context, in *SetActiveTeamInput) (*SetActiveTeamOutput, error) {
	if !h.Org.TeamsEnabled() {
		return nil, huma.NewError(http.StatusNotFound, "Teams are not enabled")
	}
	sessionResp, err := h.Authenticate(ctx, in.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}
	updated, err := h.Org.SetActiveTeam(ctx, sessionResp.Session.ID, in.Body.TeamID, sessionResp.User.ID)
	if err != nil {
		if err == orgerrors.ErrTeamNotFound {
			return nil, huma.NewError(http.StatusNotFound, "Team not found")
		}
		return nil, humatypes.RespondErr(err)
	}
	return &SetActiveTeamOutput{Body: *updated}, nil
}
