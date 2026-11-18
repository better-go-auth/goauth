package compattest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	bearer "github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/stretchr/testify/require"
)

// TestGoMirror_Bearer mirrors src/tests/compat/client/test-bearer.mjs in pure Go.
func TestGoMirror_Bearer(t *testing.T) {
	s := NewServer(t,
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	c := newBearerTestClient(s.URL)
	email := fmt.Sprintf("go-bearer-%d@example.com", time.Now().UnixNano())
	password := "Password123!"

	// [1] signUp.email with Bearer token capture (no cookies)
	res := c.post(t, "/api/auth/sign-up/email", map[string]any{
		"email":    email,
		"password": password,
		"name":     "Bearer Token User",
	})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.NotEmpty(t, c.bearerTok, "expected set-auth-token header on signUp")

	// [2] getSession via Bearer token
	sess1 := c.get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, sess1.Status, string(sess1.Body))
	var sessBody struct {
		Session map[string]any `json:"session"`
		User    struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	sess1.JSON(t, &sessBody)
	require.NotNil(t, sessBody.Session)
	require.Equal(t, email, sessBody.User.Email)

	// [3] signOut via Bearer
	outRes := c.post(t, "/api/auth/sign-out", nil)
	require.Equal(t, http.StatusOK, outRes.Status, string(outRes.Body))
	revokedTok := c.bearerTok
	c.bearerTok = ""

	// [4] getSession without token returns null
	sess2 := c.get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, sess2.Status, string(sess2.Body))
	require.Equal(t, "null", strings.TrimSpace(string(sess2.Body)))

	// [5] getSession with revoked Bearer token returns null
	c.bearerTok = revokedTok
	sessRevoked := c.get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, sessRevoked.Status, string(sessRevoked.Body))
	require.Equal(t, "null", strings.TrimSpace(string(sessRevoked.Body)))
	c.bearerTok = ""

	// [6] signIn.email captures new Bearer token
	inRes := c.post(t, "/api/auth/sign-in/email", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusOK, inRes.Status, string(inRes.Body))
	require.NotEmpty(t, c.bearerTok, "expected set-auth-token header on signIn")

	// [7] getSession with new Bearer token
	sess3 := c.get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, sess3.Status, string(sess3.Body))
	sess3.JSON(t, &sessBody)
	require.NotNil(t, sessBody.Session)
	require.Equal(t, email, sessBody.User.Email)
}
