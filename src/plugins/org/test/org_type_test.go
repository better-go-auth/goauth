package org_test

import (
	"context"
	"testing"

	serv_interfaces "github.com/better-go-auth/goauth/src/app/services/interfaces"
	"github.com/better-go-auth/goauth/src/models"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestOrgType_SessionSyncOnActiveOrgChange(t *testing.T) {
	ctx := context.Background()
	env := helpers.SetupTestEnv(t, true)

	ownerID, _ := setupOrgUser(t, env, "orgtype-owner@example.com", "", "")

	// 1. Create a session for the user without active org
	sess, err := env.Auth.Sessions().Create(ctx, &models.User{Base: models.Base{ID: ownerID}}, serv_interfaces.SessionMeta{}, serv_interfaces.SessionCreateOptions{})
	require.NoError(t, err)
	require.Nil(t, sess.Session.ActiveOrganizationID)
	require.Nil(t, sess.Session.ActiveOrganizationType)

	// 2. Create Org 1 with OrgType = "business" and keepCurrentActiveOrganization = false (default)
	bizType := "business"
	org1, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name:    "Business Corp",
		Slug:    "business-corp",
		OrgType: &bizType,
	})
	require.NoError(t, err)
	require.NotNil(t, org1.OrgType)
	require.Equal(t, "business", *org1.OrgType)

	// Verify OrgToResponse exports orgType
	orgResp := orgdtos.OrgToResponse(org1)
	require.NotNil(t, orgResp.OrgType)
	require.Equal(t, "business", *orgResp.OrgType)

	// 3. Set Org 1 as active organization on the session
	updatedSess1, err := env.OrgService.SetActiveOrganization(ctx, sess.Session.ID, &org1.ID, ownerID, "")
	require.NoError(t, err)
	require.NotNil(t, updatedSess1.Session.ActiveOrganizationID)
	require.Equal(t, org1.ID, *updatedSess1.Session.ActiveOrganizationID)
	require.NotNil(t, updatedSess1.Session.ActiveOrganizationType)
	require.Equal(t, "business", *updatedSess1.Session.ActiveOrganizationType)

	// Verify session read from manager / DB carries activeOrganizationType
	fetchedSess1, err := env.Auth.Sessions().Get(ctx, sess.Session.Token)
	require.NoError(t, err)
	require.NotNil(t, fetchedSess1.Session.ActiveOrganizationType)
	require.Equal(t, "business", *fetchedSess1.Session.ActiveOrganizationType)

	// 4. Create Org 2 with OrgType = "enterprise"
	entType := "enterprise"
	org2, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name:                          "Enterprise Inc",
		Slug:                          "enterprise-inc",
		OrgType:                       &entType,
		KeepCurrentActiveOrganization: true,
	})
	require.NoError(t, err)
	require.Equal(t, "enterprise", *org2.OrgType)

	// 5. Switch active organization to Org 2
	updatedSess2, err := env.OrgService.SetActiveOrganization(ctx, sess.Session.ID, &org2.ID, ownerID, "")
	require.NoError(t, err)
	require.Equal(t, org2.ID, *updatedSess2.Session.ActiveOrganizationID)
	require.NotNil(t, updatedSess2.Session.ActiveOrganizationType)
	require.Equal(t, "enterprise", *updatedSess2.Session.ActiveOrganizationType)

	// Verify session in store updated to enterprise
	fetchedSess2, err := env.Auth.Sessions().Get(ctx, sess.Session.Token)
	require.NoError(t, err)
	require.Equal(t, "enterprise", *fetchedSess2.Session.ActiveOrganizationType)

	// 6. Clear active organization (orgID = nil)
	clearedSess, err := env.OrgService.SetActiveOrganization(ctx, sess.Session.ID, nil, ownerID, "")
	require.NoError(t, err)
	require.Nil(t, clearedSess.Session.ActiveOrganizationID)
	require.Nil(t, clearedSess.Session.ActiveOrganizationRole)
	require.Nil(t, clearedSess.Session.ActiveOrganizationType)

	fetchedCleared, err := env.Auth.Sessions().Get(ctx, sess.Session.Token)
	require.NoError(t, err)
	require.Nil(t, fetchedCleared.Session.ActiveOrganizationID)
	require.Nil(t, fetchedCleared.Session.ActiveOrganizationType)

	// 7. Org without OrgType -> sets activeOrganizationType and orgType to nil
	org3, err := env.OrgService.CreateOrganization(ctx, ownerID, orgdtos.CreateOrgInput{
		Name: "Untyped Org",
		Slug: "untyped-org",
	})
	require.NoError(t, err)
	require.Nil(t, org3.OrgType)

	updatedSess3, err := env.OrgService.SetActiveOrganization(ctx, sess.Session.ID, &org3.ID, ownerID, "")
	require.NoError(t, err)
	require.Equal(t, org3.ID, *updatedSess3.Session.ActiveOrganizationID)
	require.Nil(t, updatedSess3.Session.ActiveOrganizationType)

	// 8. Update Org 3 to have OrgType = "community", switch again and verify
	commType := "community"
	updatedOrg3, err := env.OrgService.UpdateOrganization(ctx, org3.ID, orgdtos.UpdateOrgInput{
		OrgType: &commType,
	}, ownerID)
	require.NoError(t, err)
	require.NotNil(t, updatedOrg3.OrgType)
	require.Equal(t, "community", *updatedOrg3.OrgType)

	updatedSess4, err := env.OrgService.SetActiveOrganization(ctx, sess.Session.ID, &org3.ID, ownerID, "")
	require.NoError(t, err)
	require.NotNil(t, updatedSess4.Session.ActiveOrganizationType)
	require.Equal(t, "community", *updatedSess4.Session.ActiveOrganizationType)
}
