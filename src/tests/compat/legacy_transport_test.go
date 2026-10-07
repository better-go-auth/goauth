package compattest

import (
	"io"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
)

type legacyTokens struct {
	Body struct {
		AuthTokens struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"authTokens"`
	} `json:"body"`
}

// bare sends a request without the cookie jar, like a mobile or server-side client.
func (s *Server) bare(t *testing.T, method, path, bearer string) int {
	t.Helper()
	req, _ := http.NewRequest(method, s.URL+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestLegacyJWTOnSharedSessions(t *testing.T) {
	s := NewServer(t, WithConfig(compatMode))
	expectStatus(t, s.Post(t, "/api/auth/sign-up/email", signUpBody("legacy@example.com")), http.StatusOK)

	// legacy login creates a normal better-auth session; the refresh token is its session token
	r := s.Post(t, "/api/auth/login", map[string]any{"info": "legacy@example.com", "password": "password123"})
	expectStatus(t, r, http.StatusCreated)
	var login legacyTokens
	r.JSON(t, &login)
	access, refresh := login.Body.AuthTokens.AccessToken, login.Body.AuthTokens.RefreshToken
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens: %s", r.Body)
	}

	var sessions []map[string]any
	s.Get(t, "/api/auth/list-sessions").JSON(t, &sessions)
	if len(sessions) != 2 {
		t.Fatalf("cookie and JWT sessions must both be listed, got %d", len(sessions))
	}

	// one middleware for every client kind
	if code := s.bare(t, http.MethodGet, "/api/auth/profile", access); code != http.StatusOK {
		t.Fatalf("access JWT: %d", code)
	}
	if code := s.bare(t, http.MethodGet, "/api/auth/profile", refresh); code != http.StatusOK {
		t.Fatalf("session token as bearer: %d", code)
	}
	expectStatus(t, s.Get(t, "/api/auth/profile"), http.StatusOK) // session cookie
	if code := s.bare(t, http.MethodGet, "/api/auth/profile", "garbage-token"); code == http.StatusOK {
		t.Fatal("unknown token must be rejected")
	}

	// refresh rotates the session token by default
	r = s.Post(t, "/api/auth/refresh", map[string]any{"token": refresh})
	expectStatus(t, r, http.StatusCreated)
	var next legacyTokens
	r.JSON(t, &next)
	newRefresh := next.Body.AuthTokens.RefreshToken
	if newRefresh == "" || newRefresh == refresh {
		t.Fatalf("refresh token must rotate: %s", r.Body)
	}
	if r := s.Post(t, "/api/auth/refresh", map[string]any{"token": refresh}); r.Status == http.StatusCreated {
		t.Fatal("rotated-out refresh token must be rejected")
	}

	// logout revokes the shared session: its access token stops working and it leaves list-sessions
	expectStatus(t, s.Post(t, "/api/auth/logout", map[string]any{"token": newRefresh}), http.StatusCreated)
	if code := s.bare(t, http.MethodGet, "/api/auth/profile", next.Body.AuthTokens.AccessToken); code == http.StatusOK {
		t.Fatal("access token of a revoked session must be rejected")
	}
	s.Get(t, "/api/auth/list-sessions").JSON(t, &sessions)
	if len(sessions) != 1 {
		t.Fatalf("only the cookie session should remain, got %d", len(sessions))
	}
}

func TestLegacyRefreshWithoutRotation(t *testing.T) {
	keep := false
	s := NewServer(t, WithConfig(func(c *config.AuthConfig) {
		compatMode(c)
		c.GoAuth.Session.JWT.RotateRefreshToken = &keep
	}))
	expectStatus(t, s.Post(t, "/api/auth/sign-up/email", signUpBody("stable@example.com")), http.StatusOK)
	var login legacyTokens
	s.Post(t, "/api/auth/login", map[string]any{"info": "stable@example.com", "password": "password123"}).JSON(t, &login)
	for range 2 {
		r := s.Post(t, "/api/auth/refresh", map[string]any{"token": login.Body.AuthTokens.RefreshToken})
		expectStatus(t, r, http.StatusCreated)
		var next legacyTokens
		r.JSON(t, &next)
		if next.Body.AuthTokens.RefreshToken != login.Body.AuthTokens.RefreshToken {
			t.Fatal("without rotation the refresh token stays the same")
		}
	}
}
