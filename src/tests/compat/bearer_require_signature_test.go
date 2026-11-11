package compattest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestBearerAndAccessToken_RequireSignatureEnforcement verifies that neither access-token nor
// SessionClaims (used by AuthMiddleware.Authenticate) resolves raw opaque Bearer tokens directly,
// so opaque Bearer token verification (including RequireSignature) is enforced solely by bearer.
func TestBearerAndAccessToken_RequireSignatureEnforcement(t *testing.T) {
	setup := func(t *testing.T, bearerCfg bearerconfig.BearerConfig) *Server {
		t.Helper()
		db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:bearer_sig_%d?mode=memory&cache=shared", time.Now().UnixNano())),
			&gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)

		atCfg := accesstokenconfig.DefaultAccessTokenConfig()
		atCfg.AutoRegisterMiddleware = true
		atCfg.Session.JWT.AccessSecret = "bearer-sig-enforcement-secret-32b!"

		orgPlugin, err := org.NewWithGorm(db, orgconfig.OrgConfig{})
		require.NoError(t, err)

		return NewServer(t,
			WithDB(db),
			WithAccessTokenConfig(atCfg),
			WithPlugin(bearer.New(bearerCfg)),
			WithPlugin(orgPlugin),
			WithConfig(func(c *config.AuthConfig) {
				compatMode(c)
				c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
			}),
		)
	}

	t.Run("RequireSignature_DefaultTrue", func(t *testing.T) {
		s := setup(t, bearerconfig.DefaultConfig())
		c := newBearerTestClient(s.URL)
		email := fmt.Sprintf("sig-req-%d@example.com", time.Now().UnixNano())
		password := "Password123!"

		// 1. Sign up to obtain an HMAC-signed opaque Bearer token (`<token>.<hmac>`).
		up := c.post(t, "/api/auth/sign-up/email", map[string]any{
			"email":    email,
			"password": password,
			"name":     "Sig Required User",
		})
		require.Equal(t, http.StatusOK, up.Status, string(up.Body))
		signedTok := c.bearerTok
		require.Equal(t, 1, strings.Count(signedTok, "."), "expected signed `<tok>.<sig>` token, got %q", signedTok)
		unsignedTok := strings.SplitN(signedTok, ".", 2)[0]
		require.NotEmpty(t, unsignedTok)

		// 2. Also log in via /api/auth/login to obtain a 3-segment Access JWT.
		loginClient := newBearerTestClient(s.URL)
		loginRes := loginClient.post(t, "/api/auth/login", map[string]any{
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
		jwtTok := loginBody.Body.AuthTokens.AccessToken
		if jwtTok == "" {
			jwtTok = loginBody.Body.Token
		}
		require.Equal(t, 2, strings.Count(jwtTok, "."), "expected 3-segment Access JWT, got: %s", string(loginRes.Body))

		// 3. Valid HMAC-signed opaque Bearer token works on both /get-session and Authenticate() routes.
		c.bearerTok = signedTok
		sessSigned := c.get(t, "/api/auth/get-session")
		require.Equal(t, http.StatusOK, sessSigned.Status, string(sessSigned.Body))
		var sessOut struct {
			User struct {
				Email string `json:"email"`
			} `json:"user"`
		}
		sessSigned.JSON(t, &sessOut)
		require.Equal(t, email, sessOut.User.Email)

		orgSigned := c.get(t, "/api/auth/organization/list")
		require.Equal(t, http.StatusOK, orgSigned.Status, string(orgSigned.Body))

		// 4. Unsigned 32-char opaque token must be REJECTED on both /get-session and /organization/list.
		c.bearerTok = unsignedTok
		sessUnsigned := c.get(t, "/api/auth/get-session")
		require.Equal(t, http.StatusOK, sessUnsigned.Status, string(sessUnsigned.Body))
		require.Equal(t, "null", strings.TrimSpace(string(sessUnsigned.Body)), "unsigned token must not authenticate get-session")

		orgUnsigned := c.get(t, "/api/auth/organization/list")
		require.Equal(t, http.StatusUnauthorized, orgUnsigned.Status, "unsigned token must be rejected with 401 on Authenticate() routes: %s", string(orgUnsigned.Body))

		// 5. Tampered signature must also be REJECTED on both routes.
		c.bearerTok = unsignedTok + ".tamperedsignature"
		sessTampered := c.get(t, "/api/auth/get-session")
		require.Equal(t, http.StatusOK, sessTampered.Status, string(sessTampered.Body))
		require.Equal(t, "null", strings.TrimSpace(string(sessTampered.Body)))

		orgTampered := c.get(t, "/api/auth/organization/list")
		require.Equal(t, http.StatusUnauthorized, orgTampered.Status, string(orgTampered.Body))

		// 6. Valid 3-segment Access JWT continues to authenticate both endpoints cleanly.
		c.bearerTok = jwtTok
		sessJWT := c.get(t, "/api/auth/get-session")
		require.Equal(t, http.StatusOK, sessJWT.Status, string(sessJWT.Body))
		var jwtOut struct {
			User struct {
				Email string `json:"email"`
			} `json:"user"`
		}
		sessJWT.JSON(t, &jwtOut)
		require.Equal(t, email, jwtOut.User.Email)

		orgJWT := c.get(t, "/api/auth/organization/list")
		require.Equal(t, http.StatusOK, orgJWT.Status, string(orgJWT.Body))
	})

	t.Run("RequireSignature_Disabled", func(t *testing.T) {
		reqSig := false
		s := setup(t, bearerconfig.BearerConfig{RequireSignature: &reqSig})
		c := newBearerTestClient(s.URL)
		email := fmt.Sprintf("sig-opt-%d@example.com", time.Now().UnixNano())

		up := c.post(t, "/api/auth/sign-up/email", map[string]any{
			"email":    email,
			"password": "Password123!",
			"name":     "Unsigned Allowed User",
		})
		require.Equal(t, http.StatusOK, up.Status, string(up.Body))
		require.NotEmpty(t, c.bearerTok)
		unsignedTok := strings.SplitN(c.bearerTok, ".", 2)[0]

		// With RequireSignature: false, bearer plugin accepts the unsigned opaque token everywhere.
		c.bearerTok = unsignedTok
		sessRes := c.get(t, "/api/auth/get-session")
		require.Equal(t, http.StatusOK, sessRes.Status, string(sessRes.Body))
		var sessOut struct {
			User struct {
				Email string `json:"email"`
			} `json:"user"`
		}
		sessRes.JSON(t, &sessOut)
		require.Equal(t, email, sessOut.User.Email)

		orgRes := c.get(t, "/api/auth/organization/list")
		require.Equal(t, http.StatusOK, orgRes.Status, string(orgRes.Body))
	})
}
