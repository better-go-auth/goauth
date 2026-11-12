package compattest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	goauth "github.com/better-go-auth/goauth"
	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/config"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupSecurityPolicyServer(t *testing.T, secCfg config.SecurityConfig, atOverride func(*accesstokenconfig.AccessTokenConfig), authOverride func(*config.AuthConfig)) *Server {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:sec_policy_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)

	atCfg := accesstokenconfig.DefaultAccessTokenConfig()
	atCfg.AutoRegisterMiddleware = true
	atCfg.Session.JWT.AccessSecret = "route-security-policy-secret-32b!"
	if atOverride != nil {
		atOverride(&atCfg)
	}

	adminPlugin, err := admin.NewWithGorm(db)
	require.NoError(t, err)
	orgPlugin, err := org.NewWithGorm(db, orgconfig.OrgConfig{})
	require.NoError(t, err)

	return NewServer(t,
		WithDB(db),
		WithAccessTokenConfig(atCfg),
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(adminPlugin),
		WithPlugin(orgPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
			c.User.ChangeEmail.Enabled = true
			c.User.ChangeEmail.UpdateEmailWithoutVerification = true
			c.EmailVerification.SendVerificationEmail = func(config.EmailVerificationData, *http.Request) error {
				return nil
			}
			c.Security = secCfg
			if authOverride != nil {
				authOverride(c)
			}
		}),
	)
}

func loginForJWT(t *testing.T, sURL, email, password string) string {
	t.Helper()
	lc := newBearerTestClient(sURL)
	res := lc.post(t, "/api/auth/login", map[string]any{
		"info":     email,
		"password": password,
	})
	require.Equal(t, http.StatusCreated, res.Status, string(res.Body))
	var loginBody struct {
		Body struct {
			Token      string `json:"token"`
			AuthTokens struct {
				AccessToken string `json:"access_token"`
			} `json:"authTokens"`
		} `json:"body"`
	}
	res.JSON(t, &loginBody)
	jwtTok := loginBody.Body.AuthTokens.AccessToken
	if jwtTok == "" {
		jwtTok = loginBody.Body.Token
	}
	require.Equal(t, 2, strings.Count(jwtTok, "."), "expected 3-segment Access JWT, got: %s", string(res.Body))
	return jwtTok
}

func TestRouteSecurityPolicy_RequireBearerTokenOps(t *testing.T) {
	restrictedOps := []consts.OperationId{
		humaadapter.OpChangeEmail,
		humaadapter.OpRevokeSessions,
		humaorg.OrDeleteOrg,
		consts.OperationId(humaorg.OrDeleteOrg.Str() + "-Post"),
		humaadmin.AdminSetRole,
	}

	setup := func(t *testing.T, rejectBlocked bool) (*Server, *bearerTestClient, string, string, string) {
		s := setupSecurityPolicyServer(t, config.SecurityConfig{}, func(at *accesstokenconfig.AccessTokenConfig) {
			at.RequireBearerTokenOps = restrictedOps
			at.RejectBlockedAccessTokens = rejectBlocked
		}, nil)

		c := newBearerTestClient(s.URL)
		email := fmt.Sprintf("sec-bearer-%d@example.com", time.Now().UnixNano())
		password := "Password123!"

		up := c.post(t, "/api/auth/sign-up/email", map[string]any{
			"email":    email,
			"password": password,
			"name":     "Policy User",
		})
		require.Equal(t, http.StatusOK, up.Status, string(up.Body))
		signedBearer := c.bearerTok
		require.Equal(t, 1, strings.Count(signedBearer, "."))

		// Promote user to admin so AdminSetRole is authorized for valid tokens
		require.NoError(t, s.DB.Table("user").Where("email = ?", email).Update("role", "admin").Error)

		// Create an org using the signed bearer token so DeleteOrg target exists
		orgRes := c.post(t, "/api/auth/organization/create", map[string]any{
			"name": "Policy Org",
			"slug": fmt.Sprintf("policy-org-%d", time.Now().UnixNano()),
		})
		require.Equal(t, http.StatusCreated, orgRes.Status, string(orgRes.Body))
		var createdOrg struct {
			ID string `json:"id"`
		}
		orgRes.JSON(t, &createdOrg)
		require.NotEmpty(t, createdOrg.ID)

		jwtTok := loginForJWT(t, s.URL, email, password)
		return s, c, signedBearer, createdOrg.ID, jwtTok
	}

	t.Run("RejectBlockedAccessTokensTrue", func(t *testing.T) {
		s, c, signedBearer, orgID, jwtTok := setup(t, true)

		// 1. Access JWT still authenticates normal/unlisted endpoints
		jwtClient := newBearerTestClient(s.URL)
		jwtClient.bearerTok = jwtTok
		require.Equal(t, http.StatusOK, jwtClient.get(t, "/api/auth/get-session").Status)
		require.Equal(t, http.StatusOK, jwtClient.get(t, "/api/auth/organization/list").Status)

		// 2. Access JWT is immediately REJECTED (401 "access token not allowed") on RequireBearerTokenOps routes
		for _, tc := range []struct {
			method string
			path   string
			body   any
		}{
			{http.MethodPost, "/api/auth/change-email", map[string]any{"newEmail": "blocked-jwt@example.com"}},
			{http.MethodPost, "/api/auth/revoke-sessions", nil},
			{http.MethodDelete, "/api/auth/organization/delete", map[string]any{"organizationId": orgID}},
			{http.MethodPost, "/api/auth/organization/delete", map[string]any{"organizationId": orgID}},
			{http.MethodPost, "/api/auth/admin/set-role", map[string]any{"userId": "nonexistent", "role": "user"}},
		} {
			res := jwtClient.do(t, tc.method, tc.path, tc.body)
			require.Equal(t, http.StatusUnauthorized, res.Status, "expected 401 for Access JWT on %s %s, got: %s", tc.method, tc.path, string(res.Body))
			require.Contains(t, string(res.Body), "access token not allowed")
		}

		// 3. Signed opaque Bearer token works cleanly on those listed routes
		c.bearerTok = signedBearer
		chgRes := c.post(t, "/api/auth/change-email", map[string]any{"newEmail": fmt.Sprintf("updated-%d@example.com", time.Now().UnixNano())})
		require.Equal(t, http.StatusOK, chgRes.Status, string(chgRes.Body))

		delOrgRes := c.do(t, http.MethodDelete, "/api/auth/organization/delete", map[string]any{"organizationId": orgID})
		require.Equal(t, http.StatusOK, delOrgRes.Status, string(delOrgRes.Body))
	})

	t.Run("PassThroughByDefault", func(t *testing.T) {
		s, _, _, orgID, jwtTok := setup(t, false)

		// 1. Access JWT alone does not authenticate blocked routes — middleware passes through and downstream returns 401 without "access token not allowed"
		jwtClient := newBearerTestClient(s.URL)
		jwtClient.bearerTok = jwtTok
		res := jwtClient.post(t, "/api/auth/change-email", map[string]any{"newEmail": "passthrough-jwt@example.com"})
		require.Equal(t, http.StatusUnauthorized, res.Status, string(res.Body))
		require.NotContains(t, string(res.Body), "access token not allowed")

		// 2. When a valid session cookie is also present, pass-through lets the cookie authenticate the route
		cookieSignUp := s.Post(t, "/api/auth/sign-up/email", map[string]any{
			"email":    fmt.Sprintf("cookie-pass-%d@example.com", time.Now().UnixNano()),
			"password": "Password123!",
			"name":     "Cookie User",
		})
		require.Equal(t, http.StatusOK, cookieSignUp.Status, string(cookieSignUp.Body))

		chgBody, err := json.Marshal(map[string]any{"newEmail": fmt.Sprintf("cookie-ok-%d@example.com", time.Now().UnixNano())})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, s.URL+"/api/auth/change-email", strings.NewReader(string(chgBody)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", s.Origin)
		req.Header.Set("Authorization", "Bearer "+jwtTok)
		resp, err := s.Client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(b))
		_ = orgID
	})
}

func TestRouteSecurityPolicy_RequireFreshOps(t *testing.T) {
	secCfg := config.SecurityConfig{
		RequireFreshOps: []consts.OperationId{
			humaadapter.OpChangeEmail,
			humaorg.OrUpdateMemberRole,
			humaadmin.AdminRemoveUser,
		},
	}

	s := setupSecurityPolicyServer(t, secCfg, nil, func(c *config.AuthConfig) {
		c.Session.FreshAge = 80 * time.Millisecond
	})

	c := newBearerTestClient(s.URL)
	email := fmt.Sprintf("fresh-%d@example.com", time.Now().UnixNano())
	password := "Password123!"

	up := c.post(t, "/api/auth/sign-up/email", map[string]any{
		"email":    email,
		"password": password,
		"name":     "Fresh User",
	})
	require.Equal(t, http.StatusOK, up.Status, string(up.Body))
	signedBearer := c.bearerTok

	// Wait past FreshAge so the session becomes stale
	time.Sleep(110 * time.Millisecond)

	// 1. Unlisted routes like /get-session remain accessible on stale session
	c.bearerTok = signedBearer
	sessRes := c.get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, sessRes.Status)
	require.Contains(t, string(sessRes.Body), email)

	// 2. Listed core, org, and admin operations reject the stale session with 403 SESSION_NOT_FRESH
	for _, tc := range []struct {
		path string
		body any
	}{
		{"/api/auth/change-email", map[string]any{"newEmail": "stale-change@example.com"}},
		{"/api/auth/organization/update-member-role", map[string]any{"organizationId": "o1", "memberId": "m1", "role": "admin"}},
		{"/api/auth/admin/remove-user", map[string]any{"userId": "u1"}},
	} {
		res := c.post(t, tc.path, tc.body)
		require.Equal(t, http.StatusForbidden, res.Status, "expected 403 SESSION_NOT_FRESH on %s, got: %s", tc.path, string(res.Body))
		require.Contains(t, string(res.Body), "SESSION_NOT_FRESH")
	}

	// 3. Re-authenticating creates a fresh session that passes the freshness gate
	inRes := c.post(t, "/api/auth/sign-in/email", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusOK, inRes.Status, string(inRes.Body))
	freshEmail := fmt.Sprintf("fresh-updated-%d@example.com", time.Now().UnixNano())
	chgOK := c.post(t, "/api/auth/change-email", map[string]any{"newEmail": freshEmail})
	require.Equal(t, http.StatusOK, chgOK.Status, string(chgOK.Body))
}

func TestRouteSecurityPolicy_DefaultStrictAndPluginOriginCheck(t *testing.T) {
	strictCfg := goauth.DefaultStrictSecurityConfig()
	s := setupSecurityPolicyServer(t, strictCfg, func(at *accesstokenconfig.AccessTokenConfig) {
		at.RequireBearerTokenOps = goauth.DefaultBearerTokenOperations()
		at.RejectBlockedAccessTokens = true
	}, nil)

	// Sign up with cookie-jar client using trusted Origin
	email := fmt.Sprintf("strict-cookie-%d@example.com", time.Now().UnixNano())
	res := s.Post(t, "/api/auth/sign-up/email", map[string]any{
		"email":    email,
		"password": "Password123!",
		"name":     "Strict Cookie User",
	})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	sendCookieReq := func(originHeader string) (int, string) {
		raw, err := json.Marshal(map[string]any{
			"name": "Cookie Org",
			"slug": fmt.Sprintf("cookie-org-%d", time.Now().UnixNano()),
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, s.URL+"/api/auth/organization/create", strings.NewReader(string(raw)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		if originHeader != "" {
			req.Header.Set("Origin", originHeader)
		}
		resp, err := s.Client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(b)
	}

	// 1. Cookie-authenticated plugin mutation with missing Origin is rejected
	st, body := sendCookieReq("")
	require.Equal(t, http.StatusForbidden, st, body)

	// 2. Cookie-authenticated plugin mutation with untrusted Origin is rejected
	st, body = sendCookieReq("https://evil.example.com")
	require.Equal(t, http.StatusForbidden, st, body)

	// 3. Cookie-authenticated plugin mutation with trusted Origin succeeds
	st, body = sendCookieReq(s.Origin)
	require.Equal(t, http.StatusCreated, st, body)

	// 4. DefaultStrictSecurityConfig blocks Access JWTs on sensitive ops (e.g. /admin/remove-user)
	jwtTok := loginForJWT(t, s.URL, email, "Password123!")
	jwtClient := newBearerTestClient(s.URL)
	jwtClient.bearerTok = jwtTok
	remRes := jwtClient.post(t, "/api/auth/admin/remove-user", map[string]any{"userId": "u1"})
	require.Equal(t, http.StatusUnauthorized, remRes.Status, string(remRes.Body))
}
