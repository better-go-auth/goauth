package org_test

import (
	"context"
	"testing"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/tests/helpers"
)

// TestOrgHandler_FullFlow invokes the Org handlers directly in-process
// without HTTP networking, enabling direct line-by-line debugging of handlers and services.
func TestOrgHandler_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ctx := context.Background()

	ownerUserID, ownerAuthMap := setupOrgUser(t, env, "handler_owner@example.com", "", "")
	memberUserID, memberAuthMap := setupOrgUser(t, env, "handler_member@example.com", "", "")

	ownerAuth := humatypes.AuthHeaders{Authorization: ownerAuthMap["Authorization"]}
	memberAuth := humatypes.AuthHeaders{Authorization: memberAuthMap["Authorization"]}

	var orgID string
	var invitationID string
	var targetMemberID string

	t.Run("01 Create Organization", func(t *testing.T) {
		createInput := orgdtos.CreateOrgInput{
			Name: "Handler Org",
			Slug: "handler-org",
		}
		resp, err := env.OrgHandler.CreateOrg(ctx, &humaorg.CreateOrgInput{
			AuthHeaders: ownerAuth,
			Body:        createInput,
		})
		if err != nil {
			t.Fatalf("CreateOrg handler failed: %v", err)
		}
		if resp == nil || resp.Body.ID == "" {
			t.Fatalf("Expected created organization response with ID")
		}
		orgID = resp.Body.ID
		if resp.Body.Name != "Handler Org" {
			t.Fatalf("Expected org name 'Handler Org', got %s", resp.Body.Name)
		}
	})

	t.Run("02 Get Organization", func(t *testing.T) {
		resp, err := env.OrgHandler.GetOrg(ctx, &humaorg.GetOrgInput{
			AuthHeaders:    ownerAuth,
			OrganizationID: orgID,
		})
		if err != nil {
			t.Fatalf("GetOrg handler failed: %v", err)
		}
		if resp == nil || resp.Body.ID != orgID {
			t.Fatalf("Expected org ID %s", orgID)
		}
	})

	t.Run("03 Update Organization", func(t *testing.T) {
		// First set active org so RequireOrgRoles succeeds for update
		setActResp, err := env.OrgHandler.SetActiveOrg(ctx, &humaorg.SetActiveOrgInput{
			AuthHeaders: ownerAuth,
			Body: orgdtos.SetActiveOrgInput{
				OrganizationID: ptr(orgID),
			},
		})
		if err != nil {
			t.Fatalf("SetActiveOrg handler failed: %v", err)
		}
		if setActResp != nil && setActResp.Body.AccessToken != "" {
			ownerAuth.Authorization = "Bearer " + setActResp.Body.AccessToken
		}

		resp, err := env.OrgHandler.UpdateOrg(ctx, &humaorg.UpdateOrgInput{
			AuthHeaders: ownerAuth,
			Body: orgdtos.UpdateOrgInput{
				OrganizationID: orgID,
				Name:           ptr("Handler Org Updated"),
			},
		})
		if err != nil {
			t.Fatalf("UpdateOrg handler failed: %v", err)
		}
		if resp == nil || resp.Body.Name != "Handler Org Updated" {
			t.Fatalf("Expected updated name 'Handler Org Updated'")
		}
	})

	t.Run("04 List Organizations", func(t *testing.T) {
		resp, err := env.OrgHandler.ListOrgs(ctx, &humaorg.ListOrgsInput{
			AuthHeaders: ownerAuth,
		})
		if err != nil {
			t.Fatalf("ListOrgs handler failed: %v", err)
		}
		if resp == nil || len(resp.Body.Organizations) == 0 {
			t.Fatalf("Expected at least 1 organization in list")
		}
	})

	t.Run("05 Set Active Organization", func(t *testing.T) {
		resp, err := env.OrgHandler.SetActiveOrg(ctx, &humaorg.SetActiveOrgInput{
			AuthHeaders: ownerAuth,
			Body: orgdtos.SetActiveOrgInput{
				OrganizationID: ptr(orgID),
			},
		})
		if err != nil {
			t.Fatalf("SetActiveOrg handler failed: %v", err)
		}
		if resp == nil || resp.Body.AccessToken == "" {
			t.Fatalf("Expected valid access token in SetActiveOrg response")
		}
		ownerAuth.Authorization = "Bearer " + resp.Body.AccessToken
	})

	t.Run("06 Invite Member", func(t *testing.T) {
		resp, err := env.OrgHandler.InviteMember(ctx, &humaorg.InviteMemberInput{
			AuthHeaders: ownerAuth,
			Body: orgdtos.InviteMemberInput{
				OrganizationID: orgID,
				Email:          "handler_member@example.com",
				Role:           orgmodels.OrgRoleMember,
			},
		})
		if err != nil {
			t.Fatalf("InviteMember handler failed: %v", err)
		}
		if resp == nil || resp.Body.ID == "" {
			t.Fatalf("Expected invitation with valid ID")
		}
		invitationID = resp.Body.ID
	})

	t.Run("07 List Invitations", func(t *testing.T) {
		resp, err := env.OrgHandler.ListInvitations(ctx, &humaorg.ListInvitationsInput{
			AuthHeaders:    ownerAuth,
			OrganizationID: orgID,
		})
		if err != nil {
			t.Fatalf("ListInvitations handler failed: %v", err)
		}
		if resp == nil || len(resp.Body.Invitations) == 0 {
			t.Fatalf("Expected at least 1 invitation")
		}
	})

	t.Run("08 Get Invitation", func(t *testing.T) {
		resp, err := env.OrgHandler.GetInvitation(ctx, &humaorg.GetInvitationInput{
			AuthHeaders:  memberAuth,
			InvitationID: invitationID,
		})
		if err != nil {
			t.Fatalf("GetInvitation handler failed: %v", err)
		}
		if resp == nil || resp.Body.ID != invitationID {
			t.Fatalf("Expected invitation ID %s", invitationID)
		}
	})

	t.Run("09 Accept Invitation", func(t *testing.T) {
		resp, err := env.OrgHandler.AcceptInvitation(ctx, &humaorg.HumaInvitationInput{
			AuthHeaders: memberAuth,
			Body: orgdtos.InvitationInput{
				InvitationID: invitationID,
			},
		})
		if err != nil {
			t.Fatalf("AcceptInvitation handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Success {
			t.Fatalf("Expected success true on AcceptInvitation")
		}
	})

	t.Run("10 List Members", func(t *testing.T) {
		resp, err := env.OrgHandler.ListMembers(ctx, &humaorg.ListMembersInput{
			AuthHeaders:    ownerAuth,
			OrganizationID: orgID,
		})
		if err != nil {
			t.Fatalf("ListMembers handler failed: %v", err)
		}
		if resp == nil || len(resp.Body.Members) < 2 {
			t.Fatalf("Expected at least 2 members")
		}

		for _, m := range resp.Body.Members {
			if m.UserID == memberUserID {
				targetMemberID = m.ID
				break
			}
		}
		if targetMemberID == "" {
			t.Fatalf("Expected to find accepted member for user ID %s", memberUserID)
		}
	})

	t.Run("11 Get Member", func(t *testing.T) {
		resp, err := env.OrgHandler.GetMember(ctx, &humaorg.GetMemberInput{
			AuthHeaders:    ownerAuth,
			OrganizationID: orgID,
			UserID:         memberUserID,
		})
		if err != nil {
			t.Fatalf("GetMember handler failed: %v", err)
		}
		if resp == nil || resp.Body.UserID != memberUserID {
			t.Fatalf("Expected member with user ID %s", memberUserID)
		}
	})

	t.Run("12 Update Member Role", func(t *testing.T) {
		resp, err := env.OrgHandler.UpdateMemberRole(ctx, &humaorg.UpdateMemberRoleInput{
			AuthHeaders: ownerAuth,
			Body: orgdtos.UpdateMemberRoleInput{
				OrganizationID: orgID,
				MemberID:       targetMemberID,
				Role:           orgmodels.OrgRoleAdmin,
			},
		})
		if err != nil {
			t.Fatalf("UpdateMemberRole handler failed: %v", err)
		}
		if resp == nil || resp.Body.Role != string(orgmodels.OrgRoleAdmin) {
			t.Fatalf("Expected role '%s', got '%s'", orgmodels.OrgRoleAdmin, resp.Body.Role)
		}
	})

	t.Run("13 Remove Member", func(t *testing.T) {
		resp, err := env.OrgHandler.RemoveMember(ctx, &humaorg.RemoveMemberInput{
			AuthHeaders: ownerAuth,
			Body: orgdtos.RemoveMemberInput{
				OrganizationID: orgID,
				MemberID:       targetMemberID,
			},
		})
		if err != nil {
			t.Fatalf("RemoveMember handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Success {
			t.Fatalf("Expected success true on RemoveMember")
		}
	})

	t.Run("14 Delete Organization", func(t *testing.T) {
		resp, err := env.OrgHandler.DeleteOrg(ctx, &humaorg.DeleteOrgInput{
			AuthHeaders: ownerAuth,
			Body: orgdtos.DeleteOrgInput{
				OrganizationID: orgID,
			},
		})
		if err != nil {
			t.Fatalf("DeleteOrg handler failed: %v", err)
		}
		if resp == nil || !resp.Body.Success {
			t.Fatalf("Expected success true on DeleteOrg")
		}
	})

	_ = ownerUserID
}
