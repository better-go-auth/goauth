package test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/anonymous"
	anonconfig "github.com/better-go-auth/goauth/src/plugins/anonymous/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// ─── Harness ─────────────────────────────────────────────────────────────────

// linkRecorder records OnLinkAccount calls.
type linkRecorder struct {
	mu    sync.Mutex
	calls []anonconfig.LinkAccountData
	err   error
}

func (l *linkRecorder) onLink(_ context.Context, data anonconfig.LinkAccountData) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, data)
	return l.err
}

func (l *linkRecorder) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.calls)
}

func (l *linkRecorder) last() anonconfig.LinkAccountData {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls[len(l.calls)-1]
}

type harness struct {
	*compattest.Server
	links *linkRecorder
}

// newHarness starts goauth with extra plugins (placed before the anonymous plugin), then the anonymous
// plugin configured by cfg; OnLinkAccount defaults to the recorder.
func newHarness(t *testing.T, cfg anonconfig.AnonymousConfig, before ...plugins.Plugin) *harness {
	t.Helper()
	links := &linkRecorder{}
	if cfg.OnLinkAccount == nil {
		cfg.OnLinkAccount = links.onLink
	}
	opts := []compattest.Option{
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	}
	for _, p := range before {
		opts = append(opts, compattest.WithPlugin(p))
	}
	opts = append(opts, compattest.WithPlugin(anonymous.New(cfg)))
	s := compattest.NewServer(t, opts...)
	s.Client.Jar = nil
	return &harness{Server: s, links: links}
}

type userBody struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	IsAnonymous bool   `json:"isAnonymous"`
}

type authBody struct {
	Token *string  `json:"token"`
	User  userBody `json:"user"`
}

type errBody struct {
	Code string `json:"code"`
}

func expectError(t *testing.T, r *compattest.Response, status int, code string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s)", r.Status, status, r.Body)
	}
	var e errBody
	r.JSON(t, &e)
	if e.Code != code {
		t.Fatalf("code = %q, want %q (%s)", e.Code, code, r.Body)
	}
}

func expectOK(t *testing.T, r *compattest.Response) {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", r.Status, r.Body)
	}
}

// cookieHeader turns the response's non-expired Set-Cookie entries into a Cookie request header.
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

// signInAnonymous signs in anonymously and returns the body and cookies.
func (h *harness) signInAnonymous(t *testing.T) (authBody, string) {
	t.Helper()
	r := h.Post(t, "/api/auth/sign-in/anonymous", nil)
	expectOK(t, r)
	var b authBody
	r.JSON(t, &b)
	return b, cookieHeader(r)
}

// userExists reports whether the user id is still live.
func (h *harness) userExists(id string) bool {
	u, err := h.Auth.Repositories().FindUserByID(context.Background(), id)
	return err == nil && u != nil
}

// sessionUser returns the session user for cookies (nil when signed out).
func (h *harness) sessionUser(t *testing.T, cookies string) *userBody {
	t.Helper()
	r := h.Get(t, "/api/auth/get-session", withCookie(cookies))
	expectOK(t, r)
	var b *struct {
		User userBody `json:"user"`
	}
	r.JSON(t, &b)
	if b == nil {
		return nil
	}
	return &b.User
}

// ─── Sign in anonymously ─────────────────────────────────────────────────────

func TestSignInAnonymous(t *testing.T) {
	h := newHarness(t, anonconfig.AnonymousConfig{})

	// Step 1: an anonymous user with a generated email and session
	b, cookies := h.signInAnonymous(t)
	if b.Token == nil || *b.Token == "" || !b.User.IsAnonymous || b.User.Name != "Anonymous" {
		t.Fatalf("sign-in body = %+v", b)
	}
	if !strings.HasPrefix(b.User.Email, "temp@") || !strings.HasSuffix(b.User.Email, ".com") {
		t.Fatalf("email = %q, want temp@<id>.com", b.User.Email)
	}
	if u := h.sessionUser(t, cookies); u == nil || u.ID != b.User.ID || !u.IsAnonymous {
		t.Fatalf("get-session user = %+v", u)
	}

	// Step 2: anonymous users cannot sign in anonymously again
	expectError(t, h.Post(t, "/api/auth/sign-in/anonymous", nil, withCookie(cookies)),
		http.StatusBadRequest, "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY")

	// Step 3: isAnonymous cannot be set through update-user
	r := h.Post(t, "/api/auth/update-user", map[string]any{"isAnonymous": false}, withCookie(cookies))
	if r.Status == http.StatusOK {
		t.Fatalf("update-user isAnonymous must be rejected: %s", r.Body)
	}
	if u := h.sessionUser(t, cookies); u == nil || !u.IsAnonymous {
		t.Fatalf("user after rejected update = %+v", u)
	}
}

func TestEmailAndNameOptions(t *testing.T) {
	h := newHarness(t, anonconfig.AnonymousConfig{
		EmailDomainName: "anon.example.com",
		GenerateName:    func(context.Context, *http.Request) string { return "Guest" },
	})
	b, _ := h.signInAnonymous(t)
	if !strings.HasPrefix(b.User.Email, "temp-") || !strings.HasSuffix(b.User.Email, "@anon.example.com") || b.User.Name != "Guest" {
		t.Fatalf("user = %+v", b.User)
	}

	custom := newHarness(t, anonconfig.AnonymousConfig{GenerateRandomEmail: func(context.Context) string { return "guest-1@example.com" }})
	b, _ = custom.signInAnonymous(t)
	if b.User.Email != "guest-1@example.com" {
		t.Fatalf("custom email = %q", b.User.Email)
	}

	invalid := newHarness(t, anonconfig.AnonymousConfig{GenerateRandomEmail: func(context.Context) string { return "not-an-email" }})
	expectError(t, invalid.Post(t, "/api/auth/sign-in/anonymous", nil), http.StatusBadRequest, "INVALID_EMAIL_FORMAT")
}

// ─── Linking ─────────────────────────────────────────────────────────────────

func TestLinkOnEmailSignUp(t *testing.T) {
	h := newHarness(t, anonconfig.AnonymousConfig{})
	anon, anonCookies := h.signInAnonymous(t)

	// Step 1: signing up while anonymous links and deletes the anonymous user
	r := h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "real@example.com", "password": "Password123!", "name": "Real"},
		withCookie(anonCookies))
	expectOK(t, r)
	var up authBody
	r.JSON(t, &up)
	if up.User.IsAnonymous {
		t.Fatalf("new user must not be anonymous: %+v", up.User)
	}
	if h.links.count() != 1 {
		t.Fatalf("onLinkAccount calls = %d, want 1", h.links.count())
	}
	data := h.links.last()
	if data.AnonymousUser == nil || data.AnonymousUser.User.ID != anon.User.ID || !data.AnonymousUser.User.IsAnonymous {
		t.Fatalf("anonymousUser = %+v", data.AnonymousUser)
	}
	if data.NewUser == nil || data.NewUser.User.ID != up.User.ID || data.NewUser.Session.Token != *up.Token {
		t.Fatalf("newUser = %+v", data.NewUser)
	}
	if h.userExists(anon.User.ID) {
		t.Fatal("the anonymous user must be deleted after linking")
	}
	if u := h.sessionUser(t, anonCookies); u != nil {
		t.Fatalf("the anonymous session must be revoked, got %+v", u)
	}
	if u := h.sessionUser(t, cookieHeader(r)); u == nil || u.ID != up.User.ID {
		t.Fatalf("new session user = %+v", u)
	}

	// Step 2: sign-ups without an anonymous session do not link
	expectOK(t, h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "other@example.com", "password": "Password123!", "name": "Other"}))
	if h.links.count() != 1 {
		t.Fatalf("onLinkAccount calls = %d, want still 1", h.links.count())
	}
}

func TestLinkOnEmailSignIn(t *testing.T) {
	h := newHarness(t, anonconfig.AnonymousConfig{})
	expectOK(t, h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "real@example.com", "password": "Password123!", "name": "Real"}))
	anon, anonCookies := h.signInAnonymous(t)

	// a failed sign-in does not link
	r := h.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "real@example.com", "password": "wrong-password"}, withCookie(anonCookies))
	if r.Status == http.StatusOK || h.links.count() != 0 || !h.userExists(anon.User.ID) {
		t.Fatalf("failed sign-in must not link (status %d, calls %d)", r.Status, h.links.count())
	}

	r = h.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "real@example.com", "password": "Password123!"}, withCookie(anonCookies))
	expectOK(t, r)
	if h.links.count() != 1 || h.userExists(anon.User.ID) {
		t.Fatalf("sign-in while anonymous: calls %d, anonymous user exists %v", h.links.count(), h.userExists(anon.User.ID))
	}
}

// TestLinkOnPluginSignIn checks linking works for a plugin sign-in route mounted before the anonymous plugin.
func TestLinkOnPluginSignIn(t *testing.T) {
	h := newHarness(t, anonconfig.AnonymousConfig{}, username.New(usernameconfig.UsernameConfig{}))
	expectOK(t, h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "real@example.com", "password": "Password123!", "name": "Real", "username": "real_user"}))
	anon, anonCookies := h.signInAnonymous(t)

	r := h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "real_user", "password": "Password123!"}, withCookie(anonCookies))
	expectOK(t, r)
	if h.links.count() != 1 || h.userExists(anon.User.ID) {
		t.Fatalf("username sign-in while anonymous: calls %d, anonymous user exists %v", h.links.count(), h.userExists(anon.User.ID))
	}
}

func TestDisableDeleteAnonymousUser(t *testing.T) {
	h := newHarness(t, anonconfig.AnonymousConfig{DisableDeleteAnonymousUser: true})
	anon, anonCookies := h.signInAnonymous(t)

	// linking still calls onLinkAccount but keeps the anonymous user
	expectOK(t, h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "real@example.com", "password": "Password123!", "name": "Real"},
		withCookie(anonCookies)))
	if h.links.count() != 1 || !h.userExists(anon.User.ID) {
		t.Fatalf("calls %d, anonymous user exists %v", h.links.count(), h.userExists(anon.User.ID))
	}
	expectError(t, h.Post(t, "/api/auth/delete-anonymous-user", nil, withCookie(anonCookies)),
		http.StatusBadRequest, "DELETE_ANONYMOUS_USER_DISABLED")
}

func TestOnLinkAccountError(t *testing.T) {
	links := &linkRecorder{err: autherr.ErrForbidden.WithMessage("linking refused")}
	h := newHarness(t, anonconfig.AnonymousConfig{OnLinkAccount: links.onLink})
	anon, anonCookies := h.signInAnonymous(t)

	// the hook error becomes the response and no session cookie is handed out
	r := h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "real@example.com", "password": "Password123!", "name": "Real"},
		withCookie(anonCookies))
	if r.Status != autherr.ErrForbidden.StatusCode {
		t.Fatalf("status = %d, want %d (%s)", r.Status, autherr.ErrForbidden.StatusCode, r.Body)
	}
	if !strings.Contains(string(r.Body), "linking refused") {
		t.Fatalf("body = %s", r.Body)
	}
	if c := r.Cookie("better-auth.session_token"); c != nil {
		t.Fatalf("no session cookie expected, got %+v", c)
	}
	if links.count() != 1 || !h.userExists(anon.User.ID) {
		t.Fatalf("calls %d, anonymous user exists %v", links.count(), h.userExists(anon.User.ID))
	}
}

// ─── Delete anonymous user ───────────────────────────────────────────────────

func TestDeleteAnonymousUser(t *testing.T) {
	h := newHarness(t, anonconfig.AnonymousConfig{})

	// Step 1: signed out → 401
	expectError(t, h.Post(t, "/api/auth/delete-anonymous-user", nil), http.StatusUnauthorized, "UNAUTHORIZED")

	// Step 2: regular users are not anonymous
	r := h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "real@example.com", "password": "Password123!", "name": "Real"})
	expectOK(t, r)
	expectError(t, h.Post(t, "/api/auth/delete-anonymous-user", nil, withCookie(cookieHeader(r))),
		http.StatusForbidden, "USER_IS_NOT_ANONYMOUS")

	// Step 3: an anonymous user deletes itself; cookies are cleared
	anon, cookies := h.signInAnonymous(t)
	r = h.Post(t, "/api/auth/delete-anonymous-user", nil, withCookie(cookies))
	expectOK(t, r)
	var b struct {
		Success bool `json:"success"`
	}
	r.JSON(t, &b)
	if !b.Success {
		t.Fatalf("body = %s", r.Body)
	}
	if c := r.Cookie("better-auth.session_token"); c == nil || c.MaxAge >= 0 {
		t.Fatalf("session cookie must be expired, got %+v", c)
	}
	if h.userExists(anon.User.ID) {
		t.Fatal("anonymous user must be deleted")
	}
	if u := h.sessionUser(t, cookies); u != nil {
		t.Fatalf("session must be revoked, got %+v", u)
	}
}
