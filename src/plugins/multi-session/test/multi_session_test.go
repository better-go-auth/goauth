package test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	multisession "github.com/better-go-auth/goauth/src/plugins/multi-session"
	msconfig "github.com/better-go-auth/goauth/src/plugins/multi-session/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const (
	sessionCookie = "better-auth.session_token"
	multiPrefix   = sessionCookie + "_multi-"
	password      = "Password123!"
)

// browser is a minimal cookie jar: Set-Cookie entries are applied in order, expired ones are removed.
type browser struct {
	names   []string
	cookies map[string]string
}

func newBrowser() *browser { return &browser{cookies: map[string]string{}} }

func (b *browser) apply(r *compattest.Response) {
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
			continue
		}
		if _, ok := b.cookies[c.Name]; !ok {
			b.names = append(b.names, c.Name)
		}
		b.cookies[c.Name] = c.Value
	}
}

func (b *browser) header() string {
	var parts []string
	for _, n := range b.names {
		if v, ok := b.cookies[n]; ok {
			parts = append(parts, n+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

func (b *browser) multiCount() int {
	n := 0
	for name := range b.cookies {
		if strings.HasPrefix(name, multiPrefix) {
			n++
		}
	}
	return n
}

type env struct {
	*compattest.Server
	plugin *multisession.Plugin
}

func newEnv(t *testing.T, cfg msconfig.MultiSessionConfig) *env {
	t.Helper()
	p := multisession.New(cfg)
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

// do sends a request with the browser's cookies and stores the response cookies.
func (e *env) do(t *testing.T, b *browser, method, path string, body any) *compattest.Response {
	t.Helper()
	r := e.Do(t, method, path, body, map[string]string{"Cookie": b.header()})
	b.apply(r)
	return r
}

type authBody struct {
	Token string `json:"token"`
	User  struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

func (e *env) signUp(t *testing.T, b *browser, email string) authBody {
	t.Helper()
	r := e.do(t, b, http.MethodPost, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Multi"})
	expectStatus(t, r, http.StatusOK)
	var out authBody
	r.JSON(t, &out)
	return out
}

func (e *env) signIn(t *testing.T, b *browser, email string) authBody {
	t.Helper()
	r := e.do(t, b, http.MethodPost, "/api/auth/sign-in/email", map[string]any{"email": email, "password": password})
	expectStatus(t, r, http.StatusOK)
	var out authBody
	r.JSON(t, &out)
	return out
}

type sessionItem struct {
	Session struct {
		Token  string `json:"token"`
		UserID string `json:"userId"`
	} `json:"session"`
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

func (e *env) list(t *testing.T, b *browser) []sessionItem {
	t.Helper()
	r := e.do(t, b, http.MethodGet, "/api/auth/multi-session/list-device-sessions", nil)
	expectStatus(t, r, http.StatusOK)
	var out []sessionItem
	r.JSON(t, &out)
	return out
}

func (e *env) currentUser(t *testing.T, b *browser) string {
	t.Helper()
	r := e.do(t, b, http.MethodGet, "/api/auth/get-session", nil)
	expectStatus(t, r, http.StatusOK)
	var out *sessionItem
	r.JSON(t, &out)
	if out == nil {
		return ""
	}
	return out.User.Email
}

func (e *env) sessionExists(t *testing.T, token string) bool {
	t.Helper()
	sw, err := e.Auth.Sessions().Get(context.Background(), token)
	return err == nil && sw != nil
}

func expectStatus(t *testing.T, r *compattest.Response, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s)", r.Status, status, r.Body)
	}
}

func expectCode(t *testing.T, r *compattest.Response, status int, code string) {
	t.Helper()
	expectStatus(t, r, status)
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	r.JSON(t, &e)
	if e.Code != code {
		t.Fatalf("code = %q, want %q (%s)", e.Code, code, r.Body)
	}
}

func emails(items []sessionItem) string {
	var out []string
	for _, it := range items {
		out = append(out, it.User.Email)
	}
	return strings.Join(out, ",")
}

func TestMultiSessionCookieOnSignIn(t *testing.T) {
	e := newEnv(t, msconfig.MultiSessionConfig{})
	b := newBrowser()
	a := e.signUp(t, b, "a@example.com")
	// the multi-session cookie is named after the lowercased token and holds the signed token
	name := multiPrefix + strings.ToLower(a.Token)
	if _, ok := b.cookies[name]; !ok {
		t.Fatalf("missing multi-session cookie %s in %v", name, b.header())
	}
	if got := e.plugin.Service().CookieName(a.Token); got != name {
		t.Fatalf("CookieName = %q, want %q", got, name)
	}
	if !strings.HasPrefix(b.cookies[name], a.Token+".") {
		t.Fatalf("multi-session cookie value is not the signed token: %q", b.cookies[name])
	}
}

func TestMultiSessionListSetActiveRevoke(t *testing.T) {
	e := newEnv(t, msconfig.MultiSessionConfig{})
	b := newBrowser()
	// Step 1: two users sign in on the same device
	a := e.signUp(t, b, "a@example.com")
	bb := e.signUp(t, b, "b@example.com")
	if got := emails(e.list(t, b)); got != "a@example.com,b@example.com" {
		t.Fatalf("device sessions = %s", got)
	}
	if got := e.currentUser(t, b); got != "b@example.com" {
		t.Fatalf("active user = %s, want b", got)
	}

	// Step 2: switch to user A
	r := e.do(t, b, http.MethodPost, "/api/auth/multi-session/set-active", map[string]any{"sessionToken": a.Token})
	expectStatus(t, r, http.StatusOK)
	var active sessionItem
	r.JSON(t, &active)
	if active.User.Email != "a@example.com" || active.Session.Token != a.Token {
		t.Fatalf("set-active body = %s", r.Body)
	}
	if got := e.currentUser(t, b); got != "a@example.com" {
		t.Fatalf("active user after set-active = %s", got)
	}
	if b.multiCount() != 2 {
		t.Fatalf("set-active must not add multi-session cookies: %s", b.header())
	}

	// Step 3: unknown tokens are rejected
	expectCode(t, e.do(t, b, http.MethodPost, "/api/auth/multi-session/set-active", map[string]any{"sessionToken": "nope"}),
		http.StatusUnauthorized, "INVALID_SESSION_TOKEN")
	expectCode(t, e.do(t, b, http.MethodPost, "/api/auth/multi-session/revoke", map[string]any{"sessionToken": "nope"}),
		http.StatusUnauthorized, "INVALID_SESSION_TOKEN")

	// Step 4: revoke the inactive session of B
	r = e.do(t, b, http.MethodPost, "/api/auth/multi-session/revoke", map[string]any{"sessionToken": bb.Token})
	expectStatus(t, r, http.StatusOK)
	if strings.TrimSpace(string(r.Body)) != `{"status":true}` {
		t.Fatalf("revoke body = %s", r.Body)
	}
	if e.sessionExists(t, bb.Token) {
		t.Fatal("revoked session still exists")
	}
	if got := emails(e.list(t, b)); got != "a@example.com" {
		t.Fatalf("device sessions after revoke = %s", got)
	}
	if got := e.currentUser(t, b); got != "a@example.com" {
		t.Fatalf("active user after revoking B = %s", got)
	}

	// Step 5: revoking the last (active) session signs the device out
	expectStatus(t, e.do(t, b, http.MethodPost, "/api/auth/multi-session/revoke", map[string]any{"sessionToken": a.Token}), http.StatusOK)
	if got := e.currentUser(t, b); got != "" {
		t.Fatalf("device still signed in as %s", got)
	}
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Fatal("session cookie not cleared")
	}
}

func TestMultiSessionRevokeActiveFallsBack(t *testing.T) {
	e := newEnv(t, msconfig.MultiSessionConfig{})
	b := newBrowser()
	e.signUp(t, b, "a@example.com")
	bb := e.signUp(t, b, "b@example.com")
	// revoking the active session (B) makes A active
	expectStatus(t, e.do(t, b, http.MethodPost, "/api/auth/multi-session/revoke", map[string]any{"sessionToken": bb.Token}), http.StatusOK)
	if got := e.currentUser(t, b); got != "a@example.com" {
		t.Fatalf("active user after revoking active = %q, want a", got)
	}
}

func TestMultiSessionRevokeRequiresSession(t *testing.T) {
	e := newEnv(t, msconfig.MultiSessionConfig{})
	r := e.Post(t, "/api/auth/multi-session/revoke", map[string]any{"sessionToken": "x"})
	expectStatus(t, r, http.StatusUnauthorized)
}

func TestMultiSessionSameUserReplacesOldSession(t *testing.T) {
	e := newEnv(t, msconfig.MultiSessionConfig{})
	b := newBrowser()
	first := e.signUp(t, b, "a@example.com")
	second := e.signIn(t, b, "a@example.com")
	if e.sessionExists(t, first.Token) {
		t.Fatal("the device's older session of the same user must be revoked")
	}
	if b.multiCount() != 1 {
		t.Fatalf("multi-session cookies = %d, want 1 (%s)", b.multiCount(), b.header())
	}
	items := e.list(t, b)
	if len(items) != 1 || items[0].Session.Token != second.Token {
		t.Fatalf("device sessions = %+v", items)
	}
}

func TestMultiSessionMaximumSessions(t *testing.T) {
	e := newEnv(t, msconfig.MultiSessionConfig{MaximumSessions: 2})
	b := newBrowser()
	e.signUp(t, b, "a@example.com")
	e.signUp(t, b, "b@example.com")
	c := e.signUp(t, b, "c@example.com")
	// the third session is active but not remembered on the device
	if b.multiCount() != 2 {
		t.Fatalf("multi-session cookies = %d, want 2", b.multiCount())
	}
	if _, ok := b.cookies[multiPrefix+strings.ToLower(c.Token)]; ok {
		t.Fatal("session over the maximum got a multi-session cookie")
	}
	if got := emails(e.list(t, b)); got != "a@example.com,b@example.com" {
		t.Fatalf("device sessions = %s", got)
	}
}

func TestMultiSessionSignOutRevokesAll(t *testing.T) {
	e := newEnv(t, msconfig.MultiSessionConfig{})
	b := newBrowser()
	a := e.signUp(t, b, "a@example.com")
	bb := e.signUp(t, b, "b@example.com")
	r := e.do(t, b, http.MethodPost, "/api/auth/sign-out", map[string]any{})
	expectStatus(t, r, http.StatusOK)
	if b.multiCount() != 0 {
		t.Fatalf("multi-session cookies left after sign-out: %s", b.header())
	}
	if e.sessionExists(t, a.Token) || e.sessionExists(t, bb.Token) {
		t.Fatal("sign-out must revoke every device session")
	}
	if items := e.list(t, b); len(items) != 0 {
		t.Fatalf("device sessions after sign-out = %+v", items)
	}
}

func TestMultiSessionListIgnoresForgedCookies(t *testing.T) {
	e := newEnv(t, msconfig.MultiSessionConfig{})
	b := newBrowser()
	a := e.signUp(t, b, "a@example.com")
	// a cookie with a bad signature for another user's session is ignored
	other := newBrowser()
	o := e.signUp(t, other, "other@example.com")
	b.names = append(b.names, multiPrefix+strings.ToLower(o.Token))
	b.cookies[multiPrefix+strings.ToLower(o.Token)] = o.Token + ".forged"
	items := e.list(t, b)
	if len(items) != 1 || items[0].Session.Token != a.Token {
		t.Fatalf("device sessions = %+v", items)
	}
	expectCode(t, e.do(t, b, http.MethodPost, "/api/auth/multi-session/set-active", map[string]any{"sessionToken": o.Token}),
		http.StatusUnauthorized, "INVALID_SESSION_TOKEN")
	// no cookies at all: an empty list
	r := e.Get(t, "/api/auth/multi-session/list-device-sessions")
	expectStatus(t, r, http.StatusOK)
	if strings.TrimSpace(string(r.Body)) != "[]" {
		t.Fatalf("list without cookies = %s", r.Body)
	}
}

func TestMultiSessionSetActiveDeadSessionExpiresCookie(t *testing.T) {
	e := newEnv(t, msconfig.MultiSessionConfig{})
	b := newBrowser()
	a := e.signUp(t, b, "a@example.com")
	e.signUp(t, b, "b@example.com")
	// the session dies elsewhere (e.g. revoked from another device)
	if err := e.Auth.Sessions().Delete(context.Background(), a.Token); err != nil {
		t.Fatal(err)
	}
	r := e.do(t, b, http.MethodPost, "/api/auth/multi-session/set-active", map[string]any{"sessionToken": a.Token})
	expectCode(t, r, http.StatusUnauthorized, "INVALID_SESSION_TOKEN")
	if _, ok := b.cookies[multiPrefix+strings.ToLower(a.Token)]; ok {
		t.Fatal("multi-session cookie of a dead session must be expired")
	}
	if got := e.currentUser(t, b); got != "b@example.com" {
		t.Fatalf("active user = %s", got)
	}
}
