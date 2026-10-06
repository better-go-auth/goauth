package compattest

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

func compatMode(c *config.AuthConfig) {
	c.GoAuth.Mode = config.ModeCompat
	c.BaseURL = "http://localhost:3000"
}

func createUser(t *testing.T, s *Server, email, passwordHash string) *models.User {
	t.Helper()
	active := true
	u := &models.User{UserDto: models.UserDto{Name: "Grace Hopper", Email: email, EmailVerified: true, Active: &active, Role: "user"}}
	if err := s.DB.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	if passwordHash != "" {
		acc := &models.Account{UserID: u.ID, AccountID: email, ProviderID: models.ProvCredential, Password: &passwordHash}
		if err := s.DB.Create(acc).Error; err != nil {
			t.Fatal(err)
		}
	}
	return u
}

// signIn mints a cookie session directly (no sign-in endpoint yet) and stores its cookies in the client jar.
func signIn(t *testing.T, s *Server, u *models.User, opt sessionsvc.CreateOptions) string {
	t.Helper()
	sw, err := s.Auth.Sessions.Create(context.Background(), u, sessionsvc.Meta{IPAddress: "127.0.0.1", UserAgent: "compattest"}, opt)
	if err != nil {
		t.Fatal(err)
	}
	cookies := s.Auth.Cookies.SessionCookies(sw.Session.Token, opt.DontRemember)
	ptrs := make([]*http.Cookie, len(cookies))
	for i := range cookies {
		ptrs[i] = &cookies[i]
	}
	target, _ := url.Parse(s.URL)
	s.Jar.SetCookies(target, ptrs)
	return sw.Session.Token
}

func TestOkAndErrorEndpoints(t *testing.T) {
	s := NewServer(t, WithConfig(compatMode))

	r := s.Get(t, "/api/auth/ok")
	if r.Status != http.StatusOK || strings.TrimSpace(string(r.Body)) != `{"ok":true}` {
		t.Fatalf("ok: %d %s", r.Status, r.Body)
	}

	r = s.Get(t, "/api/auth/error?error=%3Cscript%3Ealert(1)%3C/script%3E")
	if r.Status != http.StatusOK || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("error page: %d %s", r.Status, r.Header.Get("Content-Type"))
	}
	if strings.Contains(string(r.Body), "<script>") || !strings.Contains(string(r.Body), "&lt;script&gt;") {
		t.Fatalf("error code must be HTML-escaped: %s", r.Body)
	}
}

func TestCompatRoutesOnlyInCompatMode(t *testing.T) {
	s := NewServer(t)
	if r := s.Get(t, "/api/auth/get-session"); r.Status != http.StatusNotFound {
		t.Fatalf("legacy mode must not mount get-session, got %d", r.Status)
	}
}

func TestGetSession(t *testing.T) {
	// database only, so tests can age sessions by editing rows
	s := NewServer(t, WithConfig(compatMode), WithoutSecondaryStorage())

	t.Run("no cookie returns null", func(t *testing.T) {
		r := s.Get(t, "/api/auth/get-session")
		if r.Status != http.StatusOK || strings.TrimSpace(string(r.Body)) != "null" {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("missing no-store: %v", r.Header)
		}
	})

	u := createUser(t, s, "grace@example.com", "")
	tok := signIn(t, s, u, sessionsvc.CreateOptions{})

	t.Run("valid cookie returns session and user", func(t *testing.T) {
		r := s.Get(t, "/api/auth/get-session")
		if r.Status != http.StatusOK {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
		AssertJSONShape(t, r.Body, "get_session")
		var body struct {
			Session struct{ Token string }
			User    struct{ Email string }
		}
		r.JSON(t, &body)
		if body.Session.Token != tok || body.User.Email != "grace@example.com" {
			t.Fatalf("unexpected body %s", r.Body)
		}
		if r.Cookie("better-auth.session_token") != nil {
			t.Fatal("fresh session must not be re-issued")
		}
	})

	t.Run("due session slides and re-sets the cookie", func(t *testing.T) {
		old := time.Now().UTC().Add(5 * 24 * time.Hour)
		s.DB.Model(&models.Session{}).Where("token = ?", tok).Update("expires_at", old)
		r := s.Get(t, "/api/auth/get-session")
		c := r.Cookie("better-auth.session_token")
		if c == nil || c.MaxAge != 7*24*3600 {
			t.Fatalf("expected refreshed cookie, got %v", r.Header.Values("Set-Cookie"))
		}
		var row models.Session
		s.DB.Where("token = ?", tok).Take(&row)
		if !row.ExpiresAt.After(old.Add(24 * time.Hour)) {
			t.Fatalf("expires_at not extended: %v", row.ExpiresAt)
		}
	})

	t.Run("disableRefresh skips the update", func(t *testing.T) {
		s.DB.Model(&models.Session{}).Where("token = ?", tok).Update("expires_at", time.Now().UTC().Add(5*24*time.Hour))
		r := s.Get(t, "/api/auth/get-session?disableRefresh=true")
		if r.Cookie("better-auth.session_token") != nil {
			t.Fatal("disableRefresh must not re-issue the cookie")
		}
	})

	t.Run("revoked session clears cookies", func(t *testing.T) {
		if err := s.Auth.Sessions.Delete(context.Background(), tok); err != nil {
			t.Fatal(err)
		}
		r := s.Get(t, "/api/auth/get-session")
		if strings.TrimSpace(string(r.Body)) != "null" {
			t.Fatalf("expected null, got %s", r.Body)
		}
		if c := r.Cookie("better-auth.session_token"); c == nil || c.MaxAge >= 0 {
			t.Fatalf("expected cookie deletion, got %v", r.Header.Values("Set-Cookie"))
		}
	})

	t.Run("POST requires deferSessionRefresh", func(t *testing.T) {
		r := s.Post(t, "/api/auth/get-session", nil)
		var body struct{ Code string }
		r.JSON(t, &body)
		if r.Status != http.StatusMethodNotAllowed || body.Code != "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED" {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
}

func TestGetSessionDeferredRefresh(t *testing.T) {
	s := NewServer(t, WithConfig(func(c *config.AuthConfig) {
		compatMode(c)
		c.Session.DeferSessionRefresh = true
	}), WithoutSecondaryStorage())
	u := createUser(t, s, "defer@example.com", "")
	tok := signIn(t, s, u, sessionsvc.CreateOptions{})
	s.DB.Model(&models.Session{}).Where("token = ?", tok).Update("expires_at", time.Now().UTC().Add(5*24*time.Hour))

	r := s.Get(t, "/api/auth/get-session")
	var body struct{ NeedsRefresh *bool }
	r.JSON(t, &body)
	if body.NeedsRefresh == nil || !*body.NeedsRefresh || r.Cookie("better-auth.session_token") != nil {
		t.Fatalf("GET must only report needsRefresh: %s", r.Body)
	}

	r = s.Post(t, "/api/auth/get-session", nil)
	if r.Status != http.StatusOK || r.Cookie("better-auth.session_token") == nil {
		t.Fatalf("POST must refresh: %d %s", r.Status, r.Body)
	}
}

func TestDontRememberSessionIsNotRefreshed(t *testing.T) {
	s := NewServer(t, WithConfig(compatMode), WithoutSecondaryStorage())
	u := createUser(t, s, "nr@example.com", "")
	tok := signIn(t, s, u, sessionsvc.CreateOptions{DontRemember: true})
	s.DB.Model(&models.Session{}).Where("token = ?", tok).Update("expires_at", time.Now().UTC().Add(time.Hour))

	r := s.Get(t, "/api/auth/get-session")
	if r.Status != http.StatusOK || strings.TrimSpace(string(r.Body)) == "null" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r.Cookie("better-auth.session_token") != nil {
		t.Fatal("dont_remember sessions must not be refreshed")
	}
}

func TestPasswordRehashOnLegacyLogin(t *testing.T) {
	s := NewServer(t, WithConfig(func(c *config.AuthConfig) {
		compatMode(c)
		c.EmailAndPassword.RehashPasswords = true
	}))
	hash, _ := authcrypto.HashPasswordBcrypt("password-123")
	u := createUser(t, s, "rehash@example.com", hash)

	r := s.Post(t, "/api/auth/login", map[string]string{"info": "rehash@example.com", "password": "password-123"})
	if r.Status >= 300 {
		t.Fatalf("login: %d %s", r.Status, r.Body)
	}
	var acc models.Account
	s.DB.Where("user_id = ?", u.ID).Take(&acc)
	if authcrypto.HashFormat(*acc.Password) != authcrypto.FormatScrypt {
		t.Fatalf("password was not upgraded: %s", *acc.Password)
	}
	if r := s.Post(t, "/api/auth/login", map[string]string{"info": "rehash@example.com", "password": "password-123"}); r.Status >= 300 {
		t.Fatalf("login with upgraded hash: %d %s", r.Status, r.Body)
	}
}
