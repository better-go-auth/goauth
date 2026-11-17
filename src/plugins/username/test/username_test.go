package test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// ─── Harness ─────────────────────────────────────────────────────────────────

type harness struct {
	*compattest.Server
	plugin *username.Plugin
}

// newHarness starts the real goauth server with the username plugin; configure tweaks the AuthConfig.
func newHarness(t *testing.T, cfg usernameconfig.UsernameConfig, configure ...func(*config.AuthConfig)) *harness {
	t.Helper()
	p := username.New(cfg)
	s := compattest.NewServer(t,
		compattest.WithPlugin(p),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
			for _, fn := range configure {
				fn(c)
			}
		}),
	)
	// cookies are passed explicitly so several users can share one server
	s.Client.Jar = nil
	return &harness{Server: s, plugin: p}
}

type userBody struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	Username        *string `json:"username"`
	DisplayUsername *string `json:"displayUsername"`
}

type authBody struct {
	Redirect bool     `json:"redirect"`
	Token    *string  `json:"token"`
	URL      *string  `json:"url"`
	User     userBody `json:"user"`
}

type errBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
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

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// signUp posts /sign-up/email with extra body fields.
func (h *harness) signUp(t *testing.T, email string, extra map[string]any) *compattest.Response {
	t.Helper()
	body := map[string]any{"email": email, "password": "Password123!", "name": "User"}
	for k, v := range extra {
		body[k] = v
	}
	return h.Post(t, "/api/auth/sign-up/email", body)
}

// mustSignUp signs a user up and returns its body and cookies.
func (h *harness) mustSignUp(t *testing.T, email string, extra map[string]any) (authBody, string) {
	t.Helper()
	r := h.signUp(t, email, extra)
	expectOK(t, r)
	var b authBody
	r.JSON(t, &b)
	return b, cookieHeader(r)
}

// ─── Sign-up ─────────────────────────────────────────────────────────────────

func TestSignUpWithUsername(t *testing.T) {
	h := newHarness(t, usernameconfig.UsernameConfig{})

	// Step 1: the username is lowercased; displayUsername keeps the original
	b, cookies := h.mustSignUp(t, "alice@example.com", map[string]any{"username": "Alice_01"})
	if str(b.User.Username) != "alice_01" || str(b.User.DisplayUsername) != "Alice_01" {
		t.Fatalf("user = %+v, want username alice_01 / displayUsername Alice_01", b.User)
	}

	// Step 2: get-session reports both fields
	r := h.Get(t, "/api/auth/get-session", withCookie(cookies))
	expectOK(t, r)
	var sess struct {
		User userBody `json:"user"`
	}
	r.JSON(t, &sess)
	if str(sess.User.Username) != "alice_01" || str(sess.User.DisplayUsername) != "Alice_01" {
		t.Fatalf("get-session user = %+v", sess.User)
	}

	// Step 3: displayUsername alone fills the username
	b2, _ := h.mustSignUp(t, "bob@example.com", map[string]any{"displayUsername": "Bob.Smith"})
	if str(b2.User.Username) != "bob.smith" || str(b2.User.DisplayUsername) != "Bob.Smith" {
		t.Fatalf("user = %+v, want bob.smith / Bob.Smith", b2.User)
	}

	// Step 4: both given are kept apart
	b3, _ := h.mustSignUp(t, "carol@example.com", map[string]any{"username": "carol", "displayUsername": "Carol C"})
	if str(b3.User.Username) != "carol" || str(b3.User.DisplayUsername) != "Carol C" {
		t.Fatalf("user = %+v", b3.User)
	}

	// Step 5: no username at all is fine (NULL, not "")
	b4, _ := h.mustSignUp(t, "dave@example.com", nil)
	if b4.User.Username != nil || b4.User.DisplayUsername != nil {
		t.Fatalf("user without username = %+v", b4.User)
	}
	h.mustSignUp(t, "erin@example.com", nil)
}

func TestSignUpUsernameValidation(t *testing.T) {
	h := newHarness(t, usernameconfig.UsernameConfig{})
	h.mustSignUp(t, "alice@example.com", map[string]any{"username": "alice_01"})

	cases := []struct {
		name     string
		username any
		code     string
	}{
		{"duplicate (normalized)", "ALICE_01", "USERNAME_IS_ALREADY_TAKEN"},
		{"too short", "ab", "USERNAME_TOO_SHORT"},
		{"too long", strings.Repeat("a", 31), "USERNAME_TOO_LONG"},
		{"invalid characters", "bad name!", "INVALID_USERNAME"},
		{"not a string", 123, "INVALID_USERNAME"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := h.signUp(t, "new-"+strings.ReplaceAll(tc.name, " ", "")+"@example.com", map[string]any{"username": tc.username})
			expectError(t, r, http.StatusBadRequest, tc.code)
		})
	}

	// the failed sign-ups created no user
	if u, _ := h.Auth.Repositories().FindUserByEmail(context.Background(), "new-tooshort@example.com"); u != nil {
		t.Fatal("a rejected sign-up must not create the user")
	}
}

// ─── Sign in with username ───────────────────────────────────────────────────

func TestSignInUsername(t *testing.T) {
	h := newHarness(t, usernameconfig.UsernameConfig{})
	up, _ := h.mustSignUp(t, "alice@example.com", map[string]any{"username": "Alice_01"})

	// Step 1: case-insensitive sign-in returns {redirect, token, user} and session cookies
	r := h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "ALICE_01", "password": "Password123!"})
	expectOK(t, r)
	var b authBody
	r.JSON(t, &b)
	if b.Redirect || b.Token == nil || *b.Token == "" || b.User.ID != up.User.ID || str(b.User.Username) != "alice_01" {
		t.Fatalf("sign-in body = %s", r.Body)
	}
	if r.Cookie("better-auth.session_token") == nil {
		t.Fatalf("missing session cookie: %v", r.Header.Values("Set-Cookie"))
	}

	// Step 2: wrong password and unknown users get the same 401
	expectError(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "alice_01", "password": "wrong-password"}),
		http.StatusUnauthorized, "INVALID_USERNAME_OR_PASSWORD")
	expectError(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "nobody", "password": "Password123!"}),
		http.StatusUnauthorized, "INVALID_USERNAME_OR_PASSWORD")
	expectError(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "", "password": "Password123!"}),
		http.StatusUnauthorized, "INVALID_USERNAME_OR_PASSWORD")

	// Step 3: malformed usernames answer 422
	expectError(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "ab", "password": "x"}),
		http.StatusUnprocessableEntity, "USERNAME_TOO_SHORT")
	expectError(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "bad name", "password": "x"}),
		http.StatusUnprocessableEntity, "INVALID_USERNAME")

	// Step 4: callbackURL → redirect + Location
	r = h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "alice_01", "password": "Password123!", "callbackURL": "/dashboard"})
	expectOK(t, r)
	r.JSON(t, &b)
	if !b.Redirect || str(b.URL) != "/dashboard" || r.Header.Get("Location") != "/dashboard" {
		t.Fatalf("callback sign-in = %s (Location %q)", r.Body, r.Header.Get("Location"))
	}
	expectError(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "alice_01", "password": "Password123!", "callbackURL": "https://evil.example"}),
		http.StatusForbidden, "INVALID_CALLBACK_URL")

	// Step 5: rememberMe=false → session cookie without Max-Age
	r = h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "alice_01", "password": "Password123!", "rememberMe": false})
	expectOK(t, r)
	if c := r.Cookie("better-auth.session_token"); c == nil || c.MaxAge != 0 {
		t.Fatalf("rememberMe=false session cookie = %+v", c)
	}
}

func TestSignInUsernameRequiresVerifiedEmail(t *testing.T) {
	var mu sync.Mutex
	sent := 0
	h := newHarness(t, usernameconfig.UsernameConfig{}, func(c *config.AuthConfig) {
		c.EmailAndPassword.RequireEmailVerification = true
		c.EmailVerification.SendOnSignIn = true
		c.EmailVerification.SendVerificationEmail = func(config.EmailVerificationData, *http.Request) error {
			mu.Lock()
			defer mu.Unlock()
			sent++
			return nil
		}
	})
	expectOK(t, h.signUp(t, "alice@example.com", map[string]any{"username": "alice"}))
	mu.Lock()
	before := sent
	mu.Unlock()

	// unverified users are rejected and get a new verification email
	expectError(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "alice", "password": "Password123!"}),
		http.StatusForbidden, "EMAIL_NOT_VERIFIED")
	mu.Lock()
	defer mu.Unlock()
	if sent != before+1 {
		t.Fatalf("verification emails sent on sign-in = %d, want 1", sent-before)
	}
}

// ─── Is username available ───────────────────────────────────────────────────

func TestIsUsernameAvailable(t *testing.T) {
	h := newHarness(t, usernameconfig.UsernameConfig{})
	h.mustSignUp(t, "alice@example.com", map[string]any{"username": "alice"})

	check := func(name string, want bool) {
		t.Helper()
		r := h.Post(t, "/api/auth/is-username-available", map[string]any{"username": name})
		expectOK(t, r)
		var b struct {
			Available bool `json:"available"`
		}
		r.JSON(t, &b)
		if b.Available != want {
			t.Fatalf("available(%q) = %v, want %v", name, b.Available, want)
		}
	}
	check("alice", false)
	check("ALICE", false)
	check("bob", true)
	expectError(t, h.Post(t, "/api/auth/is-username-available", map[string]any{"username": "ab"}), http.StatusUnprocessableEntity, "USERNAME_TOO_SHORT")
	expectError(t, h.Post(t, "/api/auth/is-username-available", map[string]any{"username": "no way"}), http.StatusUnprocessableEntity, "INVALID_USERNAME")
	expectError(t, h.Post(t, "/api/auth/is-username-available", map[string]any{"username": ""}), http.StatusUnprocessableEntity, "INVALID_USERNAME")
}

// ─── Update user ─────────────────────────────────────────────────────────────

func TestUpdateUserUsername(t *testing.T) {
	h := newHarness(t, usernameconfig.UsernameConfig{})
	_, aliceCookies := h.mustSignUp(t, "alice@example.com", map[string]any{"username": "alice"})
	_, bobCookies := h.mustSignUp(t, "bob@example.com", map[string]any{"username": "bob"})

	session := func(cookies string) userBody {
		t.Helper()
		r := h.Get(t, "/api/auth/get-session", withCookie(cookies))
		expectOK(t, r)
		var b struct {
			User userBody `json:"user"`
		}
		r.JSON(t, &b)
		return b.User
	}

	// Step 1: change the username (normalized); displayUsername is left alone
	r := h.Post(t, "/api/auth/update-user", map[string]any{"username": "Alice.New"}, withCookie(aliceCookies))
	expectOK(t, r)
	aliceCookies = mergeCookies(aliceCookies, cookieHeader(r))
	if u := session(aliceCookies); str(u.Username) != "alice.new" || str(u.DisplayUsername) != "alice" {
		t.Fatalf("after update = %+v", u)
	}

	// Step 2: another user's username is taken; keeping your own is fine
	expectError(t, h.Post(t, "/api/auth/update-user", map[string]any{"username": "BOB"}, withCookie(aliceCookies)),
		http.StatusBadRequest, "USERNAME_IS_ALREADY_TAKEN")
	expectOK(t, h.Post(t, "/api/auth/update-user", map[string]any{"username": "bob", "name": "Bobby"}, withCookie(bobCookies)))

	// Step 3: validation errors are 400
	expectError(t, h.Post(t, "/api/auth/update-user", map[string]any{"username": "x"}, withCookie(aliceCookies)),
		http.StatusBadRequest, "USERNAME_TOO_SHORT")

	// Step 4: displayUsername can be updated on its own
	r = h.Post(t, "/api/auth/update-user", map[string]any{"displayUsername": "Alice The Great"}, withCookie(aliceCookies))
	expectOK(t, r)
	aliceCookies = mergeCookies(aliceCookies, cookieHeader(r))
	if u := session(aliceCookies); str(u.Username) != "alice.new" || str(u.DisplayUsername) != "Alice The Great" {
		t.Fatalf("after display update = %+v", u)
	}

	// Step 5: the new username signs in, the old one no longer does
	expectOK(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "alice.new", "password": "Password123!"}))
	expectError(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "alice", "password": "Password123!"}),
		http.StatusUnauthorized, "INVALID_USERNAME_OR_PASSWORD")
}

// mergeCookies overlays the cookies of next onto base (same names are replaced).
func mergeCookies(base, next string) string {
	if next == "" {
		return base
	}
	vals := map[string]string{}
	var order []string
	for _, h := range []string{base, next} {
		for _, part := range strings.Split(h, "; ") {
			name, value, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			if _, seen := vals[name]; !seen {
				order = append(order, name)
			}
			vals[name] = value
		}
	}
	parts := make([]string, 0, len(order))
	for _, n := range order {
		parts = append(parts, n+"="+vals[n])
	}
	return strings.Join(parts, "; ")
}

// ─── Options ─────────────────────────────────────────────────────────────────

func TestCustomOptions(t *testing.T) {
	h := newHarness(t, usernameconfig.UsernameConfig{
		MinUsernameLength: 5,
		MaxUsernameLength: 8,
		// digits are not allowed
		UsernameValidator: func(v string) bool { return !strings.ContainsAny(v, "0123456789") },
		// display usernames must not contain "admin"
		DisplayUsernameValidator:     func(v string) bool { return !strings.Contains(strings.ToLower(v), "admin") },
		UsernameNormalization:        func(v string) string { return strings.ToUpper(v) },
		DisplayUsernameNormalization: func(v string) string { return strings.TrimSpace(v) },
	})

	expectError(t, h.signUp(t, "a@example.com", map[string]any{"username": "abcd"}), http.StatusBadRequest, "USERNAME_TOO_SHORT")
	expectError(t, h.signUp(t, "a@example.com", map[string]any{"username": "abcdefghi"}), http.StatusBadRequest, "USERNAME_TOO_LONG")
	expectError(t, h.signUp(t, "a@example.com", map[string]any{"username": "abc12"}), http.StatusBadRequest, "INVALID_USERNAME")
	expectError(t, h.signUp(t, "a@example.com", map[string]any{"username": "hello", "displayUsername": "Admin"}), http.StatusBadRequest, "INVALID_DISPLAY_USERNAME")

	b, _ := h.mustSignUp(t, "a@example.com", map[string]any{"username": "hello", "displayUsername": "  Hello  "})
	if str(b.User.Username) != "HELLO" || str(b.User.DisplayUsername) != "Hello" {
		t.Fatalf("user = %+v", b.User)
	}
	expectOK(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "hello", "password": "Password123!"}))
}

func TestValidationOrderPostNormalization(t *testing.T) {
	// the validator only accepts lowercase; post-normalization validates the lowercased value
	lower := func(v string) bool { return v == strings.ToLower(v) }
	h := newHarness(t, usernameconfig.UsernameConfig{
		UsernameValidator: lower,
		ValidationOrder:   usernameconfig.ValidationOrder{Username: usernameconfig.PostNormalization},
	})
	b, _ := h.mustSignUp(t, "a@example.com", map[string]any{"username": "MixedCase"})
	if str(b.User.Username) != "mixedcase" {
		t.Fatalf("user = %+v", b.User)
	}

	pre := newHarness(t, usernameconfig.UsernameConfig{UsernameValidator: lower})
	expectError(t, pre.signUp(t, "a@example.com", map[string]any{"username": "MixedCase"}), http.StatusBadRequest, "INVALID_USERNAME")
}

func TestWithoutNormalization(t *testing.T) {
	h := newHarness(t, usernameconfig.UsernameConfig{DisableUsernameNormalization: true})
	b, _ := h.mustSignUp(t, "a@example.com", map[string]any{"username": "CaseKept"})
	if str(b.User.Username) != "CaseKept" {
		t.Fatalf("user = %+v", b.User)
	}
	expectError(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "casekept", "password": "Password123!"}),
		http.StatusUnauthorized, "INVALID_USERNAME_OR_PASSWORD")
	expectOK(t, h.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "CaseKept", "password": "Password123!"}))
}

// TestBeforeUserCreateHook covers users created outside /sign-up/email (admin, plugins): the database hook
// validates and normalizes their username.
func TestBeforeUserCreateHook(t *testing.T) {
	h := newHarness(t, usernameconfig.UsernameConfig{})
	svc := h.plugin.Service()
	ctx := context.Background()
	h.mustSignUp(t, "taken@example.com", map[string]any{"username": "taken"})

	// Step 1: normalized, displayUsername defaults to the username as given
	name := "New_User"
	u := &models.User{}
	u.Username = &name
	if err := svc.BeforeUserCreate(ctx, u); err != nil {
		t.Fatal(err)
	}
	if str(u.Username) != "new_user" || str(u.DisplayUsername) != "New_User" {
		t.Fatalf("user = %s / %s", str(u.Username), str(u.DisplayUsername))
	}

	// Step 2: taken and malformed usernames are rejected
	taken := "TAKEN"
	u = &models.User{}
	u.Username = &taken
	if err := svc.BeforeUserCreate(ctx, u); err == nil || !strings.Contains(err.Error(), "USERNAME_IS_ALREADY_TAKEN") {
		t.Fatalf("taken username: err = %v", err)
	}
	short := "ab"
	u = &models.User{}
	u.Username = &short
	if err := svc.BeforeUserCreate(ctx, u); err == nil || !strings.Contains(err.Error(), "USERNAME_TOO_SHORT") {
		t.Fatalf("short username: err = %v", err)
	}

	// Step 3: an empty username becomes NULL
	empty := ""
	u = &models.User{}
	u.Username = &empty
	if err := svc.BeforeUserCreate(ctx, u); err != nil || u.Username != nil {
		t.Fatalf("empty username: err = %v, username = %s", err, str(u.Username))
	}
}

// TestWithoutPlugin checks core ignores username fields on sign-up when the plugin is not installed.
func TestWithoutPlugin(t *testing.T) {
	s := compattest.NewServer(t)
	s.Client.Jar = nil
	r := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "a@example.com", "password": "Password123!", "name": "A", "username": "alice"})
	expectOK(t, r)
	var b authBody
	r.JSON(t, &b)
	if b.User.Username != nil {
		t.Fatalf("username without the plugin = %q", *b.User.Username)
	}
	expectOK(t, s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "b@example.com", "password": "Password123!", "name": "B"}))
	if s.Get(t, "/api/auth/sign-in/username").Status == http.StatusOK {
		t.Fatal("/sign-in/username must not exist without the plugin")
	}
}
