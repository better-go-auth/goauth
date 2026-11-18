package compattest

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	constant "github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/config"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	jwttoken "github.com/better-go-auth/goauth/src/plugins/access-token/jwttoken"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type claimsSnapshotOutput struct {
	Body struct {
		ActiveOrgID   string `json:"activeOrgId"`
		ActiveOrgRole string `json:"activeOrgRole"`
		ActiveTeamID  string `json:"activeTeamId"`
		CompanyCtx    string `json:"companyCtx"`
	}
}

// TestAccessToken_ActiveOrgAndTeamSync verifies both layers of the stale JWT claims fix:
// 1. Existing Access JWTs immediately observe live session activeOrgId/activeOrgRole/activeTeamId in context.
// 2. Mutations (set-active, set-active-team, unset/leave) re-mint a fresh Access JWT via set-auth-token.
func TestAccessToken_ActiveOrgAndTeamSync(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:at_org_sync_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)

	accessSecret := "access-org-sync-test-secret-32-bytes!"
	atCfg := accesstokenconfig.DefaultAccessTokenConfig()
	atCfg.AutoRegisterMiddleware = true
	atCfg.Session.JWT.AccessSecret = accessSecret

	orgPlugin, err := org.NewWithGorm(db, orgconfig.OrgConfig{
		Teams: &orgconfig.TeamsConfig{Enabled: true},
	})
	require.NoError(t, err)

	s := NewServer(t,
		WithDB(db),
		WithAccessTokenConfig(atCfg),
		WithPlugin(orgPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Mount a protected test route to inspect context claims attached by access-token middleware
	huma.Register(s.API, huma.Operation{
		OperationID: "TestClaimsSnapshot",
		Method:      http.MethodGet,
		Path:        "/test/claims",
	}, func(ctx context.Context, _ *struct{}) (*claimsSnapshotOutput, error) {
		out := &claimsSnapshotOutput{}
		if c, ok := ctx.Value(constant.CtxClaims.Str()).(token.CustomClaims); ok {
			out.Body.ActiveOrgID = c.ActiveOrgId
			out.Body.ActiveOrgRole = c.ActiveOrgRole
			out.Body.ActiveTeamID = c.ActiveTeamId
		}
		if comp, ok := ctx.Value(constant.CTXCompany_ID.Str()).(string); ok {
			out.Body.CompanyCtx = comp
		}
		return out, nil
	})

	_ = accesstoken.PluginID // reference check

	email := fmt.Sprintf("at-org-%d@example.com", time.Now().UnixNano())
	password := "Password123!"

	// Step 1: Register and login via /api/auth/login to obtain an Access JWT
	c := newBearerTestClient(s.URL)
	up := c.post(t, "/api/auth/sign-up/email", map[string]any{
		"email":    email,
		"password": password,
		"name":     "JWT Sync User",
	})
	require.Equal(t, http.StatusOK, up.Status, string(up.Body))

	loginRes := c.post(t, "/api/auth/login", map[string]any{
		"info":     email,
		"password": password,
	})
	require.Equal(t, http.StatusCreated, loginRes.Status, string(loginRes.Body))
	var loginBody struct {
		Body struct {
			Token      string `json:"token"`
			AuthTokens struct {
				AccessToken string `json:"access_token"`
			} `json:"authTokens"`
		} `json:"body"`
	}
	loginRes.JSON(t, &loginBody)
	initialJWT := loginBody.Body.AuthTokens.AccessToken
	if initialJWT == "" {
		initialJWT = loginBody.Body.Token
	}
	require.Equal(t, 2, strings.Count(initialJWT, "."), "expected 3-segment Access JWT, got: %s", string(loginRes.Body))

	initialClaims, err := jwttoken.ValidateAccessToken(initialJWT, accessSecret)
	require.NoError(t, err)
	require.Empty(t, initialClaims.ActiveOrgId)
	require.Empty(t, initialClaims.ActiveTeamId)

	// Client 1 stays pinned to stale initialJWT; Client 2 updates on set-auth-token
	staleClient := newBearerTestClient(s.URL)
	staleClient.bearerTok = initialJWT
	freshClient := newBearerTestClient(s.URL)
	freshClient.bearerTok = initialJWT

	// Step 2: Create organization with KeepCurrentActiveOrganization=true so active org stays unset first
	orgRes := freshClient.post(t, "/api/auth/organization/create", map[string]any{
		"name":                          "Sync Org",
		"slug":                          fmt.Sprintf("sync-org-%d", time.Now().UnixNano()),
		"keepCurrentActiveOrganization": true,
	})
	require.Equal(t, http.StatusOK, orgRes.Status, string(orgRes.Body))
	var createdOrg orgdtos.OrgResponse
	orgRes.JSON(t, &createdOrg)

	// Step 3: SetActiveOrganization -> verify Layer 2 (set-auth-token fresh JWT) AND Layer 1 (stale JWT context sync)
	setOrgRes := freshClient.post(t, "/api/auth/organization/set-active", map[string]any{
		"organizationId": createdOrg.ID,
	})
	require.Equal(t, http.StatusOK, setOrgRes.Status, string(setOrgRes.Body))
	newJWT1 := setOrgRes.Header.Get("set-auth-token")
	require.NotEmpty(t, newJWT1, "expected fresh access JWT in set-auth-token header")
	require.NotEqual(t, initialJWT, newJWT1)
	require.Contains(t, strings.ToLower(setOrgRes.Header.Get("Access-Control-Expose-Headers")), "set-auth-token")

	claims1, err := jwttoken.ValidateAccessToken(newJWT1, accessSecret)
	require.NoError(t, err)
	require.Equal(t, createdOrg.ID, claims1.ActiveOrgId)
	require.Equal(t, "owner", claims1.ActiveOrgRole)

	// Using stale initialJWT must STILL observe updated activeOrgId & activeOrgRole in CtxClaims & CTXCompany_ID!
	snapRes := staleClient.get(t, "/test/claims")
	require.Equal(t, http.StatusOK, snapRes.Status, string(snapRes.Body))
	var snap claimsSnapshotOutput
	snapRes.JSON(t, &snap.Body)
	require.Equal(t, createdOrg.ID, snap.Body.ActiveOrgID)
	require.Equal(t, "owner", snap.Body.ActiveOrgRole)
	require.Equal(t, createdOrg.ID, snap.Body.CompanyCtx)

	// Step 4: SetActiveTeam -> verify fresh JWT contains activeTeamId & stale JWT sees activeTeamId
	teamRes := freshClient.post(t, "/api/auth/organization/create-team", map[string]any{
		"organizationId": createdOrg.ID,
		"name":           "Core Team",
	})
	require.Equal(t, http.StatusOK, teamRes.Status, string(teamRes.Body))
	var team orgdtos.TeamResponse
	teamRes.JSON(t, &team)

	addTmRes := freshClient.post(t, "/api/auth/organization/add-team-member", map[string]any{
		"organizationId": createdOrg.ID,
		"teamId":         team.ID,
		"userId":         claims1.UserID,
	})
	require.Equal(t, http.StatusOK, addTmRes.Status, string(addTmRes.Body))

	setTeamRes := freshClient.post(t, "/api/auth/organization/set-active-team", map[string]any{
		"teamId": team.ID,
	})
	require.Equal(t, http.StatusOK, setTeamRes.Status, string(setTeamRes.Body))
	newJWT2 := setTeamRes.Header.Get("set-auth-token")
	require.NotEmpty(t, newJWT2, "expected fresh access JWT on set-active-team")

	claims2, err := jwttoken.ValidateAccessToken(newJWT2, accessSecret)
	require.NoError(t, err)
	require.Equal(t, createdOrg.ID, claims2.ActiveOrgId)
	require.Equal(t, "owner", claims2.ActiveOrgRole)
	require.Equal(t, team.ID, claims2.ActiveTeamId)

	// Prevent staleClient from adopting newJWT2 during snapshot inspection
	staleClient.bearerTok = initialJWT
	snapRes = staleClient.get(t, "/test/claims")
	require.Equal(t, http.StatusOK, snapRes.Status, string(snapRes.Body))
	snapRes.JSON(t, &snap.Body)
	require.Equal(t, team.ID, snap.Body.ActiveTeamID)

	// Step 5: Unset active organization (nil) -> clears claims in both re-minted JWT and stale-JWT context
	unsetRes := freshClient.post(t, "/api/auth/organization/set-active", map[string]any{
		"organizationId": nil,
	})
	require.Equal(t, http.StatusOK, unsetRes.Status, string(unsetRes.Body))
	newJWT3 := unsetRes.Header.Get("set-auth-token")
	require.NotEmpty(t, newJWT3)
	claims3, err := jwttoken.ValidateAccessToken(newJWT3, accessSecret)
	require.NoError(t, err)
	require.Empty(t, claims3.ActiveOrgId)
	require.Empty(t, claims3.ActiveOrgRole)

	// Even token newJWT1 (which carried createdOrg.ID) now sees empty ActiveOrgId & CompanyCtx
	staleWithOrgJWT := newBearerTestClient(s.URL)
	staleWithOrgJWT.bearerTok = newJWT1
	snapRes = staleWithOrgJWT.get(t, "/test/claims")
	require.Equal(t, http.StatusOK, snapRes.Status, string(snapRes.Body))
	snapRes.JSON(t, &snap.Body)
	require.Empty(t, snap.Body.ActiveOrgID)
	require.Empty(t, snap.Body.ActiveOrgRole)
	require.Empty(t, snap.Body.CompanyCtx)
}
