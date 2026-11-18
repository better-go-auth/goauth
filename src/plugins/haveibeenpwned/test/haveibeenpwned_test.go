package test

import (
	"context"
	"crypto/sha1" //nolint:gosec // the range API is keyed by SHA-1
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/haveibeenpwned"
	hibpconfig "github.com/better-go-auth/goauth/src/plugins/haveibeenpwned/config"
	"github.com/better-go-auth/goauth/src/plugins/haveibeenpwned/services"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const (
	pwned = "password123"      // in the fake breach corpus
	safe  = "Un1que-Pa55w0rd!" // not in it
)

// ─── fake range API ──────────────────────────────────────────────────────────

// rangeAPI is a fake Pwned Passwords range API: GET /range/<prefix> answers the suffixes of its corpus
// with that prefix plus padding lines, like the real API with Add-Padding.
type rangeAPI struct {
	*httptest.Server
	mu       sync.Mutex
	prefixes []string
	headers  []http.Header
	status   int
	hits     atomic.Int32
}

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s)) //nolint:gosec // test corpus
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func newRangeAPI(t *testing.T, corpus ...string) *rangeAPI {
	t.Helper()
	api := &rangeAPI{status: http.StatusOK}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.hits.Add(1)
		prefix := strings.TrimPrefix(r.URL.Path, "/range/")
		api.mu.Lock()
		api.prefixes = append(api.prefixes, prefix)
		api.headers = append(api.headers, r.Header.Clone())
		status := api.status
		api.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		var lines []string
		for _, p := range corpus {
			if h := sha1Hex(p); h[:5] == prefix {
				lines = append(lines, h[5:]+":42")
			}
		}
		// padding entries (count 0), lower-case like some mirrors return them
		lines = append(lines, "0000000000000000000000000000000000A:0", strings.ToLower("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")+":0")
		_, _ = fmt.Fprint(w, strings.Join(lines, "\r\n"))
	}))
	t.Cleanup(api.Close)
	return api
}

func (a *rangeAPI) setStatus(s int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = s
}

func (a *rangeAPI) lastRequest(t *testing.T) (string, http.Header) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.prefixes) == 0 {
		t.Fatal("range API not called")
	}
	return a.prefixes[len(a.prefixes)-1], a.headers[len(a.headers)-1]
}

// ─── helpers ─────────────────────────────────────────────────────────────────

type env struct {
	*compattest.Server
	api        *rangeAPI
	resetMu    sync.Mutex
	resetToken string
}

func newEnv(t *testing.T, cfg hibpconfig.HaveIBeenPwnedConfig, mutate ...func(*config.AuthConfig)) *env {
	t.Helper()
	e := &env{api: newRangeAPI(t, pwned)}
	cfg.APIURL = e.api.URL + "/range/"
	e.Server = compattest.NewServer(t,
		compattest.WithPlugin(haveibeenpwned.New(cfg)),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.EmailAndPassword.SendResetPassword = func(d config.ResetPasswordData, _ *http.Request) error {
				e.resetMu.Lock()
				e.resetToken = d.Token
				e.resetMu.Unlock()
				return nil
			}
			for _, m := range mutate {
				m(c)
			}
		}),
	)
	e.Client.Jar = nil
	return e
}

func expectError(t *testing.T, r *compattest.Response, status int, code, message string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s)", r.Status, status, r.Body)
	}
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	r.JSON(t, &e)
	if e.Code != code || e.Message != message {
		t.Fatalf("error = %s, want %s %q", r.Body, code, message)
	}
}

func (e *env) signUp(t *testing.T, email, password string) *compattest.Response {
	t.Helper()
	return e.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Pwned"})
}

func sessionCookie(r *compattest.Response) string {
	if c := r.Cookie("better-auth.session_token"); c != nil {
		return c.Name + "=" + c.Value
	}
	return ""
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestSignUpRejectsCompromisedPassword(t *testing.T) {
	e := newEnv(t, hibpconfig.HaveIBeenPwnedConfig{})
	r := e.signUp(t, "pwned@example.com", pwned)
	expectError(t, r, http.StatusBadRequest, services.CodePasswordCompromised, services.MsgPasswordCompromised)

	// only the 5-character prefix left the server, with better-auth's headers
	prefix, h := e.api.lastRequest(t)
	if prefix != sha1Hex(pwned)[:5] {
		t.Fatalf("prefix = %q", prefix)
	}
	if h.Get("Add-Padding") != "true" || h.Get("User-Agent") != "BetterAuth Password Checker" {
		t.Fatalf("headers = %v", h)
	}
	// the user was not created
	r = e.signUp(t, "pwned@example.com", safe)
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up after rejection = %d: %s", r.Status, r.Body)
	}
}

func TestSignInIsNotChecked(t *testing.T) {
	e := newEnv(t, hibpconfig.HaveIBeenPwnedConfig{Paths: []string{"/change-password"}})
	// sign-up is not in the custom paths: the compromised password is accepted
	if r := e.signUp(t, "legacy@example.com", pwned); r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	before := e.api.hits.Load()
	r := e.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "legacy@example.com", "password": pwned})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-in = %d: %s", r.Status, r.Body)
	}
	if e.api.hits.Load() != before {
		t.Fatal("sign-in must not call the range API")
	}
}

func TestChangePassword(t *testing.T) {
	e := newEnv(t, hibpconfig.HaveIBeenPwnedConfig{})
	r := e.signUp(t, "change@example.com", safe)
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	cookie := map[string]string{"Cookie": sessionCookie(r)}

	// better-auth hashes the new password before checking the current one, so the breach check wins
	r = e.Post(t, "/api/auth/change-password", map[string]any{"currentPassword": "wrong-password", "newPassword": pwned}, cookie)
	expectError(t, r, http.StatusBadRequest, services.CodePasswordCompromised, services.MsgPasswordCompromised)

	r = e.Post(t, "/api/auth/change-password", map[string]any{"currentPassword": safe, "newPassword": "An0ther-Unique!"}, cookie)
	if r.Status != http.StatusOK {
		t.Fatalf("change-password = %d: %s", r.Status, r.Body)
	}
}

func TestResetPassword(t *testing.T) {
	e := newEnv(t, hibpconfig.HaveIBeenPwnedConfig{CustomPasswordCompromisedMessage: "Pick another password"})
	if r := e.signUp(t, "reset@example.com", safe); r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	r := e.Post(t, "/api/auth/request-password-reset", map[string]any{"email": "reset@example.com"})
	if r.Status != http.StatusOK {
		t.Fatalf("request-password-reset = %d: %s", r.Status, r.Body)
	}
	e.resetMu.Lock()
	token := e.resetToken
	e.resetMu.Unlock()
	if token == "" {
		t.Fatal("no reset token")
	}
	// custom message, the token stays usable
	r = e.Post(t, "/api/auth/reset-password", map[string]any{"token": token, "newPassword": pwned})
	expectError(t, r, http.StatusBadRequest, services.CodePasswordCompromised, "Pick another password")
	r = e.Post(t, "/api/auth/reset-password", map[string]any{"token": token, "newPassword": "Fresh-Unique-1!"})
	if r.Status != http.StatusOK {
		t.Fatalf("reset-password = %d: %s", r.Status, r.Body)
	}
}

func TestDisabled(t *testing.T) {
	disabled := false
	e := newEnv(t, hibpconfig.HaveIBeenPwnedConfig{Enabled: &disabled})
	if r := e.signUp(t, "off@example.com", pwned); r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	if e.api.hits.Load() != 0 {
		t.Fatal("disabled plugin called the API")
	}
}

func TestAPIFailures(t *testing.T) {
	e := newEnv(t, hibpconfig.HaveIBeenPwnedConfig{})
	e.api.setStatus(http.StatusServiceUnavailable)
	r := e.signUp(t, "down@example.com", safe)
	expectError(t, r, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Failed to check password. Status: 503")

	// unreachable API
	svc := services.New(hibpconfig.HaveIBeenPwnedConfig{APIURL: "http://127.0.0.1:1/range/"}, "/api/auth")
	err := svc.CheckPassword(context.Background(), safe)
	if err == nil || !strings.Contains(err.Error(), services.MsgCheckFailed) {
		t.Fatalf("err = %v", err)
	}
}

func TestDuplicateSignUpWithVerificationStillChecks(t *testing.T) {
	// with requireEmailVerification an existing email gets a fake success, but better-auth still hashes (and
	// checks) the password first
	e := newEnv(t, hibpconfig.HaveIBeenPwnedConfig{}, func(c *config.AuthConfig) {
		c.EmailAndPassword.RequireEmailVerification = true
	})
	if r := e.signUp(t, "dup@example.com", safe); r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	r := e.signUp(t, "dup@example.com", pwned)
	expectError(t, r, http.StatusBadRequest, services.CodePasswordCompromised, services.MsgPasswordCompromised)
}

func TestCheckPasswordUnit(t *testing.T) {
	api := newRangeAPI(t, pwned)
	svc := services.New(hibpconfig.HaveIBeenPwnedConfig{APIURL: api.URL + "/range/"}, "")
	ctx := context.Background()
	if err := svc.CheckPassword(ctx, pwned); err == nil {
		t.Fatal("compromised password accepted")
	}
	if err := svc.CheckPassword(ctx, safe); err != nil {
		t.Fatalf("safe password: %v", err)
	}
	// empty passwords are not looked up
	before := api.hits.Load()
	if err := svc.CheckPassword(ctx, ""); err != nil || api.hits.Load() != before {
		t.Fatalf("empty password: err=%v", err)
	}
	// without a request in ctx the hook does nothing (server-side calls)
	if err := svc.BeforeHash(ctx, pwned); err != nil {
		t.Fatalf("BeforeHash outside HTTP: %v", err)
	}
	// with a request on a configured path it checks
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email", nil)
	if err := svc.BeforeHash(config.WithHTTPRequest(ctx, req), pwned); err == nil {
		t.Fatal("BeforeHash on /sign-up/email accepted a compromised password")
	}
	req = httptest.NewRequest(http.MethodPost, "/api/auth/update-user", nil)
	if err := svc.BeforeHash(config.WithHTTPRequest(ctx, req), pwned); err != nil {
		t.Fatalf("BeforeHash on another path: %v", err)
	}
}

func TestConcurrentSignUps(t *testing.T) {
	e := newEnv(t, hibpconfig.HaveIBeenPwnedConfig{})
	var wg sync.WaitGroup
	var wrong atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pw, want := safe, http.StatusOK
			if i%2 == 0 {
				pw, want = pwned, http.StatusBadRequest
			}
			if r := e.signUp(t, fmt.Sprintf("c%d@example.com", i), pw); r.Status != want {
				wrong.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if wrong.Load() != 0 {
		t.Fatalf("%d sign-ups got the wrong status", wrong.Load())
	}
}
