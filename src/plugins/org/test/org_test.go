package org_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/oklog/ulid/v2"
)

func isSuccess(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated
}

func ptr[T any](v T) *T {
	return &v
}

func setupOrgUser(t *testing.T, env *helpers.TestEnv, email string, orgID, orgRole string) (string, map[string]string) {
	user := &models.User{
		UserDto: models.UserDto{
			FirstName:     "Org",
			LastName:      "User",
			Email:         ptr(email),
			EmailVerified: true,
			Role:          enums.User,
		},
	}
	if err := env.DB.Create(user).Error; err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	sessionID := ulid.Make().String()
	var opt *models.SessionOpt
	if orgID != "" && orgRole != "" {
		opt = &models.SessionOpt{
			ActiveOrgID: ptr(orgID),
			OrgRoleID:   ptr(orgRole),
		}
	} else {
		// Provide default org context to satisfy claims check
		opt = &models.SessionOpt{
			ActiveOrgID: ptr("init-org"),
			OrgRoleID:   ptr(string(orgmodels.OrgRoleOwner)),
		}
	}

	tokens, err := env.Auth.IAuthServices.CreateSession(context.Background(), sessionID, enums.User.S(), user.ID, opt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	return user.ID, map[string]string{"Authorization": "Bearer " + tokens.AccessToken}
}

func TestOrgE2E_FullFlow(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ownerUserID, ownerAuthHeader := setupOrgUser(t, env, "owner@example.com", "", "")
	memberUserID, memberAuthHeader := setupOrgUser(t, env, "member@example.com", "", "")

	var orgID string
	var invitationID string
	var targetMemberID string

	t.Run("01 Create Organization", func(t *testing.T) {
		createInput := orgdtos.CreateOrgInput{
			Name: "Acme Corp",
			Slug: "acme-corp",
		}
		resp, body := env.PostJSON("/api/auth/organization/create", createInput, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("CreateOrg failed: status %d, body: %s", resp.StatusCode, body)
		}

		var createResp orgdtos.OrgResponse
		if err := json.Unmarshal([]byte(body), &createResp); err != nil {
			t.Fatalf("Failed to decode CreateOrg response: %v, raw: %s", err, body)
		}
		orgID = createResp.ID
		if orgID == "" {
			t.Fatalf("Expected non-empty organization ID")
		}
		if createResp.Name != "Acme Corp" {
			t.Fatalf("Expected organization name 'Acme Corp', got %s", createResp.Name)
		}
	})

	t.Run("02 Get Organization", func(t *testing.T) {
		path := fmt.Sprintf("/api/auth/organization/get-full-organization?organizationId=%s", orgID)
		resp, body := env.GetJSON(path, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("GetOrg failed: status %d, body: %s", resp.StatusCode, body)
		}

		var getResp orgdtos.OrgResponse
		if err := json.Unmarshal([]byte(body), &getResp); err != nil {
			t.Fatalf("Failed to decode GetOrg response: %v, raw: %s", err, body)
		}
		if getResp.ID != orgID {
			t.Fatalf("Expected org ID %s, got %s", orgID, getResp.ID)
		}
	})

	t.Run("03 Update Organization", func(t *testing.T) {
		updateInput := orgdtos.UpdateOrgInput{
			OrganizationID: orgID,
			Name:           ptr("Acme International"),
		}
		resp, body := env.PostJSON("/api/auth/organization/update", updateInput, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("UpdateOrg failed: status %d, body: %s", resp.StatusCode, body)
		}

		var updateResp orgdtos.OrgResponse
		if err := json.Unmarshal([]byte(body), &updateResp); err != nil {
			t.Fatalf("Failed to decode UpdateOrg response: %v, raw: %s", err, body)
		}
		if updateResp.Name != "Acme International" {
			t.Fatalf("Expected updated name 'Acme International', got %s", updateResp.Name)
		}
	})

	t.Run("04 List Organizations", func(t *testing.T) {
		resp, body := env.GetJSON("/api/auth/organization/list", ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("ListOrgs failed: status %d, body: %s", resp.StatusCode, body)
		}

		var listResp struct {
			Organizations []orgdtos.OrgResponse `json:"organizations"`
		}
		if err := json.Unmarshal([]byte(body), &listResp); err != nil {
			t.Fatalf("Failed to decode ListOrgs response: %v, raw: %s", err, body)
		}
		if len(listResp.Organizations) == 0 {
			t.Fatalf("Expected at least 1 organization, got 0")
		}
	})

	t.Run("05 Set Active Organization", func(t *testing.T) {
		setInput := orgdtos.SetActiveOrgInput{
			OrganizationID: ptr(orgID),
		}
		resp, body := env.PostJSON("/api/auth/organization/set-active", setInput, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("SetActiveOrg failed: status %d, body: %s", resp.StatusCode, body)
		}

		var tokenResp models.AuthTokens
		if err := json.Unmarshal([]byte(body), &tokenResp); err != nil {
			t.Fatalf("Failed to decode SetActiveOrg response: %v, raw: %s", err, body)
		}
		if tokenResp.AccessToken != "" {
			ownerAuthHeader = map[string]string{"Authorization": "Bearer " + tokenResp.AccessToken}
		}
	})

	t.Run("06 Invite Member", func(t *testing.T) {
		inviteInput := orgdtos.InviteMemberInput{
			OrganizationID: orgID,
			Email:          "member@example.com",
			Role:           orgmodels.OrgRoleMember,
		}
		resp, body := env.PostJSON("/api/auth/organization/invite-member", inviteInput, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("InviteMember failed: status %d, body: %s", resp.StatusCode, body)
		}

		var inviteResp orgdtos.InvitationResponse
		if err := json.Unmarshal([]byte(body), &inviteResp); err != nil {
			t.Fatalf("Failed to decode InviteMember response: %v, raw: %s", err, body)
		}
		invitationID = inviteResp.ID
		if invitationID == "" {
			t.Fatalf("Expected non-empty invitation ID")
		}
		if inviteResp.Email != "member@example.com" {
			t.Fatalf("Expected invited email 'member@example.com', got %s", inviteResp.Email)
		}
	})

	t.Run("07 List Invitations", func(t *testing.T) {
		path := fmt.Sprintf("/api/auth/organization/list-invitations?organizationId=%s", orgID)
		resp, body := env.GetJSON(path, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("ListInvitations failed: status %d, body: %s", resp.StatusCode, body)
		}

		var listInvs struct {
			Invitations []orgdtos.InvitationResponse `json:"invitations"`
		}
		if err := json.Unmarshal([]byte(body), &listInvs); err != nil {
			t.Fatalf("Failed to decode ListInvitations response: %v, raw: %s", err, body)
		}
		if len(listInvs.Invitations) == 0 {
			t.Fatalf("Expected at least 1 invitation, got 0")
		}
	})

	t.Run("08 Get Invitation", func(t *testing.T) {
		path := fmt.Sprintf("/api/auth/organization/get-invitation?invitationId=%s", invitationID)
		resp, body := env.GetJSON(path, memberAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("GetInvitation failed: status %d, body: %s", resp.StatusCode, body)
		}

		var getInv orgdtos.InvitationResponse
		if err := json.Unmarshal([]byte(body), &getInv); err != nil {
			t.Fatalf("Failed to decode GetInvitation response: %v, raw: %s", err, body)
		}
		if getInv.ID != invitationID {
			t.Fatalf("Expected invitation ID %s, got %s", invitationID, getInv.ID)
		}
	})

	t.Run("09 Accept Invitation", func(t *testing.T) {
		acceptInput := orgdtos.InvitationInput{
			InvitationID: invitationID,
		}
		resp, body := env.PostJSON("/api/auth/organization/accept-invitation", acceptInput, memberAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("AcceptInvitation failed: status %d, body: %s", resp.StatusCode, body)
		}

		var success humatypes.SuccessBody
		if err := json.Unmarshal([]byte(body), &success); err != nil {
			t.Fatalf("Failed to decode AcceptInvitation response: %v, raw: %s", err, body)
		}
		if !success.Success {
			t.Fatalf("Expected success true, got false")
		}
	})

	t.Run("10 List Members", func(t *testing.T) {
		path := fmt.Sprintf("/api/auth/organization/list-members?organizationId=%s", orgID)
		resp, body := env.GetJSON(path, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("ListMembers failed: status %d, body: %s", resp.StatusCode, body)
		}

		var listMbrs struct {
			Members []orgdtos.MemberResponse `json:"members"`
			Total   int64                    `json:"total"`
		}
		if err := json.Unmarshal([]byte(body), &listMbrs); err != nil {
			t.Fatalf("Failed to decode ListMembers response: %v, raw: %s", err, body)
		}
		if len(listMbrs.Members) < 2 {
			t.Fatalf("Expected at least 2 members, got %d", len(listMbrs.Members))
		}

		for _, m := range listMbrs.Members {
			if m.UserID == memberUserID {
				targetMemberID = m.ID
				break
			}
		}
		if targetMemberID == "" {
			t.Fatalf("Expected to find accepted member record for user ID %s", memberUserID)
		}
	})

	t.Run("11 Get Member", func(t *testing.T) {
		path := fmt.Sprintf("/api/auth/organization/get-member?organizationId=%s&userId=%s", orgID, memberUserID)
		resp, body := env.GetJSON(path, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("GetMember failed: status %d, body: %s", resp.StatusCode, body)
		}

		var getMbr orgdtos.MemberResponse
		if err := json.Unmarshal([]byte(body), &getMbr); err != nil {
			t.Fatalf("Failed to decode GetMember response: %v, raw: %s", err, body)
		}
		if getMbr.UserID != memberUserID {
			t.Fatalf("Expected member user ID %s, got %s", memberUserID, getMbr.UserID)
		}
	})

	t.Run("12 Update Member Role", func(t *testing.T) {
		updateRoleInput := orgdtos.UpdateMemberRoleInput{
			OrganizationID: orgID,
			MemberID:       targetMemberID,
			Role:           orgmodels.OrgRoleAdmin,
		}
		resp, body := env.PostJSON("/api/auth/organization/update-member-role", updateRoleInput, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("UpdateMemberRole failed: status %d, body: %s", resp.StatusCode, body)
		}

		var updatedMbr orgdtos.MemberResponse
		if err := json.Unmarshal([]byte(body), &updatedMbr); err != nil {
			t.Fatalf("Failed to decode UpdateMemberRole response: %v, raw: %s", err, body)
		}
		if updatedMbr.Role != string(orgmodels.OrgRoleAdmin) {
			t.Fatalf("Expected role '%s', got '%s'", orgmodels.OrgRoleAdmin, updatedMbr.Role)
		}
	})

	t.Run("13 Remove Member", func(t *testing.T) {
		removeInput := orgdtos.RemoveMemberInput{
			OrganizationID: orgID,
			MemberID:       targetMemberID,
		}
		resp, body := env.PostJSON("/api/auth/organization/remove-member", removeInput, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("RemoveMember failed: status %d, body: %s", resp.StatusCode, body)
		}

		var success humatypes.SuccessBody
		if err := json.Unmarshal([]byte(body), &success); err != nil {
			t.Fatalf("Failed to decode RemoveMember response: %v, raw: %s", err, body)
		}
		if !success.Success {
			t.Fatalf("Expected success true, got false")
		}
	})

	t.Run("14 Delete Organization", func(t *testing.T) {
		deleteInput := orgdtos.DeleteOrgInput{
			OrganizationID: orgID,
		}
		resp, body := env.DeleteJSON("/api/auth/organization/delete", deleteInput, ownerAuthHeader)
		if !isSuccess(resp.StatusCode) {
			t.Fatalf("DeleteOrg failed: status %d, body: %s", resp.StatusCode, body)
		}

		var success humatypes.SuccessBody
		if err := json.Unmarshal([]byte(body), &success); err != nil {
			t.Fatalf("Failed to decode DeleteOrg response: %v, raw: %s", err, body)
		}
		if !success.Success {
			t.Fatalf("Expected success true, got false")
		}
	})

	_ = ownerUserID
}
