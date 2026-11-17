package test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	onetimetoken "github.com/better-go-auth/goauth/src/plugins/one-time-token"
	ottconfig "github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
	"github.com/better-go-auth/goauth/src/plugins/one-time-token/services"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const sessionCookie = "better-auth.session_token"

type env struct {
	*compattest.Server
	plugin *onetimetoken.Plugin
}

func newEnv(t *testing.T, cfg ottconfig.OneTimeTokenConfig) *env {
	t.Helper()
	p := onetimetoken.New(cfg)
	s := compattest.NewServer(t,
		compattest.WithPlugin(p),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)
	s.Client.Jar = nil
	return &env{Server: s, plugin: p}
}

func cookieHeader(r *compattest.Response) string {
	var parts []string
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func withCookie(c string) map[string]string { return map[string]string{"Cookie": c} }

func expectStatus(t *testing.T, r *compattest.Response, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s)", r.Status, status, r.Body)
	}
}

func expectError(t *testing.T, r *compattest.Response, status int, code, message string) {
	t.Helper()
	expectStatus(t, r, status)
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	r.JSON(t, &e)
	if e.Code != code || e.Message != message {
		t.Fatalf("error = %s, want %s %q", r.Body, code, message)
	}
}

type signUpResult struct {
	Token   string
	UserID  string
	Cookies string
	Header  http.Header
}

func (e *env) signUp(t *testing.T, email string) signUpResult {
	t.Helper()
	r := e.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": "Password123!", "name": "OTT"})
	expectStatus(t, r, http.StatusOK)
	var body struct {
		Token string `json:"token"`
		User  struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(t, &body)
	return signUpResult{Token: body.Token, UserID: body.User.ID, Cookies: cookieHeader(r), Header: r.Header}
}

func (e *env) generate(t *testing.T, cookies string) string {
	t.Helper()
	r := e.Get(t, "/api/auth/one-time-token/generate", withCookie(cookies))
	expectStatus(t, r, http.StatusOK)
	var body struct {
		Token string `json:"token"`
	}
	r.JSON(t, &body)
	if body.Token == "" {
		t.Fatalf("no token: %s", r.Body)
	}
	return body.Token
}

func (e *env) verify(t *testing.T, token string) *compattest.Response {
	t.Helper()
	return e.Post(t, "/api/auth/one-time-token/verify", map[string]any{"token": token})
}

func (e *env) row(t *testing.T, identifier string) *models.Verification {
	t.Helper()
	var v models.Verification
	if err := e.DB.Where(&models.Verification{Identifier: identifier}).First(&v).Error; err != nil {
		return nil
	}
	return &v
}

func TestGenerateRequiresSession(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{})
	expectStatus(t, e.Get(t, "/api/auth/one-time-token/generate"), http.StatusUnauthorized)
}

func TestGenerateAndVerify(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{})
	u := e.signUp(t, "ott@example.com")
	token := e.generate(t, u.Cookies)

	// Step 1: the token is a 32-character random string stored as "one-time-token:<token>" → session token
	if len(token) != 32 || strings.Trim(token, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		t.Fatalf("unexpected token format %q", token)
	}
	v := e.row(t, services.IdentifierPrefix+token)
	if v == nil || v.Value != u.Token {
		t.Fatalf("verification row = %+v", v)
	}
	if d := time.Until(v.ExpiresAt); d < 2*time.Minute || d > 3*time.Minute+5*time.Second {
		t.Fatalf("expiresAt not ~3 minutes away: %v", d)
	}

	// Step 2: verify returns {session, user} and sets the session cookie
	r := e.verify(t, token)
	expectStatus(t, r, http.StatusOK)
	var body dtos.SessionWithUser
	r.JSON(t, &body)
	if body.Session.Token != u.Token || body.User.ID != u.UserID || body.User.Email != "ott@example.com" {
		t.Fatalf("verify body = %s", r.Body)
	}
	if c := r.Cookie(sessionCookie); c == nil || !strings.HasPrefix(c.Value, u.Token+".") {
		t.Fatalf("verify must set the session cookie, got %v", r.Header.Values("Set-Cookie"))
	}

	// Step 3: the token works once
	expectError(t, e.verify(t, token), http.StatusBadRequest, "INVALID_TOKEN", "Invalid token")
	if e.row(t, services.IdentifierPrefix+token) != nil {
		t.Fatal("consumed token still stored")
	}
	expectError(t, e.verify(t, "unknown"), http.StatusBadRequest, "INVALID_TOKEN", "Invalid token")
}

func TestVerifyExpiredToken(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{})
	u := e.signUp(t, "late@example.com")
	token := e.generate(t, u.Cookies)
	e.DB.Model(&models.Verification{}).Where(&models.Verification{Identifier: services.IdentifierPrefix + token}).
		Update("ExpiresAt", time.Now().Add(-time.Minute).UTC())
	expectError(t, e.verify(t, token), http.StatusBadRequest, "TOKEN_EXPIRED", "Token expired")
	// the expired token is deleted, so retrying is an invalid token
	expectError(t, e.verify(t, token), http.StatusBadRequest, "INVALID_TOKEN", "Invalid token")
}

func TestVerifyRevokedSession(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{})
	u := e.signUp(t, "gone@example.com")
	token := e.generate(t, u.Cookies)
	expectStatus(t, e.Post(t, "/api/auth/sign-out", map[string]any{}, withCookie(u.Cookies)), http.StatusOK)
	expectError(t, e.verify(t, token), http.StatusBadRequest, "SESSION_NOT_FOUND", "Session not found")
}

func TestHashedStorage(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{StoreToken: ottconfig.StoreTokenConfig{Mode: ottconfig.StoreTokenHashed}})
	u := e.signUp(t, "hash@example.com")
	token := e.generate(t, u.Cookies)
	if e.row(t, services.IdentifierPrefix+token) != nil {
		t.Fatal("hashed mode must not store the plain token")
	}
	if v := e.row(t, services.IdentifierPrefix+services.DefaultKeyHasher(token)); v == nil || v.Value != u.Token {
		t.Fatalf("hashed row = %+v", v)
	}
	expectStatus(t, e.verify(t, token), http.StatusOK)
	expectError(t, e.verify(t, token), http.StatusBadRequest, "INVALID_TOKEN", "Invalid token")
}

func TestCustomHasherAndGenerator(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{
		GenerateToken: func(_ context.Context, s *dtos.SessionWithUser) (string, error) {
			return "custom-" + s.User.ID, nil
		},
		StoreToken: ottconfig.StoreTokenConfig{Hash: func(tok string) (string, error) { return "h(" + tok + ")", nil }},
	})
	u := e.signUp(t, "custom@example.com")
	token := e.generate(t, u.Cookies)
	if token != "custom-"+u.UserID {
		t.Fatalf("token = %q", token)
	}
	if e.row(t, services.IdentifierPrefix+"h("+token+")") == nil {
		t.Fatal("custom hasher not used")
	}
	expectStatus(t, e.verify(t, token), http.StatusOK)
}

func TestDisableClientRequest(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{DisableClientRequest: true})
	u := e.signUp(t, "server@example.com")
	r := e.Get(t, "/api/auth/one-time-token/generate", withCookie(u.Cookies))
	expectError(t, r, http.StatusBadRequest, "CLIENT_REQUESTS_ARE_DISABLED", "Client requests are disabled")
	// server-side generation still works and the token verifies over HTTP
	sw, err := e.Auth.Sessions().Get(context.Background(), u.Token)
	if err != nil || sw == nil {
		t.Fatalf("session: %v", err)
	}
	token, err := e.plugin.Service().GenerateToken(context.Background(), sw)
	if err != nil {
		t.Fatal(err)
	}
	expectStatus(t, e.verify(t, token), http.StatusOK)
}

func TestDisableSetSessionCookie(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{DisableSetSessionCookie: true})
	u := e.signUp(t, "nocookie@example.com")
	r := e.verify(t, e.generate(t, u.Cookies))
	expectStatus(t, r, http.StatusOK)
	if len(r.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("verify set cookies: %v", r.Header.Values("Set-Cookie"))
	}
}

func TestExpiresInOption(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{ExpiresIn: 10 * time.Minute})
	u := e.signUp(t, "ten@example.com")
	token := e.generate(t, u.Cookies)
	v := e.row(t, services.IdentifierPrefix+token)
	if v == nil || time.Until(v.ExpiresAt) < 9*time.Minute {
		t.Fatalf("expiresAt = %+v", v)
	}
}

func TestConcurrentVerifyConsumesOnce(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{})
	u := e.signUp(t, "race@example.com")
	token := e.generate(t, u.Cookies)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.verify(t, token)
			if r.Status == http.StatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d concurrent verifications succeeded, want 1", ok)
	}
}

func TestSetOttHeaderOnNewSession(t *testing.T) {
	e := newEnv(t, ottconfig.OneTimeTokenConfig{SetOttHeaderOnNewSession: true})
	u := e.signUp(t, "header@example.com")
	ott := u.Header.Get("set-ott")
	if ott == "" {
		t.Fatalf("sign-up response has no set-ott header: %v", u.Header)
	}
	if !strings.Contains(strings.ToLower(u.Header.Get("Access-Control-Expose-Headers")), "set-ott") {
		t.Fatalf("set-ott not exposed: %q", u.Header.Get("Access-Control-Expose-Headers"))
	}
	r := e.verify(t, ott)
	expectStatus(t, r, http.StatusOK)
	var body dtos.SessionWithUser
	r.JSON(t, &body)
	if body.Session.Token != u.Token {
		t.Fatalf("set-ott token is for another session: %s", r.Body)
	}
	// responses without a new session get no token
	if h := e.Get(t, "/api/auth/ok").Header.Get("set-ott"); h != "" {
		t.Fatalf("set-ott on a response without a new session: %q", h)
	}
}
