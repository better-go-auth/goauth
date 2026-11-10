package compattest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/stretchr/testify/require"
)

// TestGoMirror_CoreFlow mirrors src/tests/compat/client/test-flow.mjs in pure Go.
func TestGoMirror_CoreFlow(t *testing.T) {
	s := NewServer(t, WithConfig(func(c *config.AuthConfig) {
		compatMode(c)
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
	}))

	email := fmt.Sprintf("go-flow-%d@example.com", time.Now().UnixNano())
	password := "Password123!"
	name := "Ada Lovelace"

	// [1] Sign up via email
	res := s.Post(t, "/api/auth/sign-up/email", map[string]any{
		"email":    email,
		"password": password,
		"name":     name,
	})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var upBody struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	res.JSON(t, &upBody)
	require.Equal(t, email, upBody.User.Email)

	// [2] getSession with auto sign-in session cookie
	sess1 := s.Get(t, "/api/auth/get-session")
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

	// [3] signOut
	outRes := s.Post(t, "/api/auth/sign-out", nil)
	require.Equal(t, http.StatusOK, outRes.Status, string(outRes.Body))

	// [4] getSession after signOut returns null
	sess2 := s.Get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, sess2.Status, string(sess2.Body))
	require.Equal(t, "null", strings.TrimSpace(string(sess2.Body)))

	// [5] signIn.email
	inRes := s.Post(t, "/api/auth/sign-in/email", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusOK, inRes.Status, string(inRes.Body))
	var inBody struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	inRes.JSON(t, &inBody)
	require.Equal(t, email, inBody.User.Email)

	// [6] getSession after signIn
	sess3 := s.Get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, sess3.Status, string(sess3.Body))
	sess3.JSON(t, &sessBody)
	require.NotNil(t, sessBody.Session)
	require.Equal(t, email, sessBody.User.Email)
}

