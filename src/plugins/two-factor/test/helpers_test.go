package test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	tfmodels "github.com/better-go-auth/goauth/src/plugins/two-factor/models"
	"github.com/better-go-auth/goauth/src/plugins/two-factor/services"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const (
	base     = "/api/auth"
	password = "password123456"
)

// env is one test server with the two-factor plugin.
type env struct {
	t      *testing.T
	s      *compattest.Server
	plugin *twofactor.Plugin
	otps   *otpBox
}

// otpBox captures the OTPs handed to SendOTP.
type otpBox struct {
	mu   sync.Mutex
	last map[string]string
	sent int
}

func (b *otpBox) send(email, otp string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.last[email] = otp
	b.sent++
}

func (b *otpBox) get(email string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last[email]
}

func baseConfig(c *config.AuthConfig) {
	c.BaseURL = "http://localhost:3000"
	c.AppName = "GoAuth Test"
	c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
}

// newEnv starts a server; withOTP wires a capturing SendOTP.
func newEnv(t *testing.T, cfg tfconfig.Config, withOTP bool, mutate ...func(*config.AuthConfig)) *env {
	t.Helper()
	box := &otpBox{last: map[string]string{}}
	if withOTP && cfg.OTPOptions.SendOTP == nil {
		cfg.OTPOptions.SendOTP = func(_ context.Context, data tfconfig.SendOTPData, _ *http.Request) error {
			box.send(data.User.Email, data.OTP)
			return nil
		}
	}
	p := twofactor.New(cfg)
	s := compattest.NewServer(t,
		compattest.WithPlugin(p),
		compattest.WithConfig(func(c *config.AuthConfig) {
			baseConfig(c)
			for _, m := range mutate {
				m(c)
			}
		}),
	)
	return &env{t: t, s: s, plugin: p, otps: box}
}

func (e *env) post(path string, body any) *compattest.Response {
	e.t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	return e.s.Post(e.t, base+path, body)
}

func (e *env) get(path string) *compattest.Response {
	e.t.Helper()
	return e.s.Get(e.t, base+path)
}

// newDevice swaps the client cookie jar (a different browser) and returns the previous one.
func (e *env) newDevice() http.CookieJar {
	old := e.s.Client.Jar
	jar, _ := cookiejar.New(nil)
	e.s.Client.Jar = jar
	return old
}

func (e *env) useJar(j http.CookieJar) { e.s.Client.Jar = j }

// cookie returns the jar's cookie "better-auth.<base>" or "".
func (e *env) cookie(name string) string {
	u, _ := url.Parse(e.s.URL)
	for _, c := range e.s.Client.Jar.Cookies(u) {
		if c.Name == "better-auth."+name {
			return c.Value
		}
	}
	return ""
}

// setCookie puts a raw cookie value into the jar.
func (e *env) setCookie(name, value string) {
	u, _ := url.Parse(e.s.URL)
	e.s.Client.Jar.SetCookies(u, []*http.Cookie{{Name: "better-auth." + name, Value: value, Path: "/"}})
}

func expectStatus(t *testing.T, r *compattest.Response, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d; body=%s", r.Status, status, r.Body)
	}
}

func expectError(t *testing.T, r *compattest.Response, status int, code string) {
	t.Helper()
	expectStatus(t, r, status)
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	r.JSON(t, &body)
	if body.Code != code {
		t.Fatalf("code = %q, want %q; body=%s", body.Code, code, r.Body)
	}
}

// signUp creates a user with a password and leaves its session in the jar.
func (e *env) signUp(email string) string {
	e.t.Helper()
	r := e.post("/sign-up/email", map[string]any{"email": email, "password": password, "name": "Test User"})
	expectStatus(e.t, r, 200)
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(e.t, &body)
	return body.User.ID
}

func (e *env) signIn(email string, extra ...map[string]any) *compattest.Response {
	e.t.Helper()
	body := map[string]any{"email": email, "password": password}
	for _, m := range extra {
		for k, v := range m {
			body[k] = v
		}
	}
	return e.post("/sign-in/email", body)
}

func (e *env) signOut() {
	e.t.Helper()
	expectStatus(e.t, e.post("/sign-out", nil), 200)
}

// session returns the current user's twoFactorEnabled and whether a session exists.
func (e *env) session() (exists bool, twoFactorEnabled bool) {
	e.t.Helper()
	r := e.get("/get-session")
	expectStatus(e.t, r, 200)
	if strings.TrimSpace(string(r.Body)) == "null" {
		return false, false
	}
	var body struct {
		User struct {
			TwoFactorEnabled bool `json:"twoFactorEnabled"`
		} `json:"user"`
	}
	r.JSON(e.t, &body)
	return true, body.User.TwoFactorEnabled
}

// enable runs /two-factor/enable and returns the raw TOTP secret and the backup codes.
func (e *env) enable() (string, []string) {
	e.t.Helper()
	r := e.post("/two-factor/enable", map[string]any{"password": password})
	expectStatus(e.t, r, 200)
	var body struct {
		TotpURI     string   `json:"totpURI"`
		BackupCodes []string `json:"backupCodes"`
	}
	r.JSON(e.t, &body)
	secret, err := services.ParseTOTPURI(body.TotpURI)
	if err != nil {
		e.t.Fatalf("parse totp uri %q: %v", body.TotpURI, err)
	}
	return secret, body.BackupCodes
}

func (e *env) totp(secret string) string {
	return services.TOTP(secret, time.Now(), 30*time.Second, 6)
}

// enableFully signs up, enables and verifies TOTP, then signs out. It returns the user id, secret and codes.
func (e *env) enableFully(email string) (string, string, []string) {
	e.t.Helper()
	id := e.signUp(email)
	secret, codes := e.enable()
	expectStatus(e.t, e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret)}), 200)
	e.signOut()
	return id, secret, codes
}

// challenge signs in and asserts the two-factor redirect; it returns the methods.
func (e *env) challenge(email string, extra ...map[string]any) []string {
	e.t.Helper()
	r := e.signIn(email, extra...)
	expectStatus(e.t, r, 200)
	var body struct {
		TwoFactorRedirect bool     `json:"twoFactorRedirect"`
		TwoFactorMethods  []string `json:"twoFactorMethods"`
		Token             string   `json:"token"`
	}
	r.JSON(e.t, &body)
	if !body.TwoFactorRedirect || body.Token != "" {
		e.t.Fatalf("expected twoFactorRedirect without token, got %s", r.Body)
	}
	return body.TwoFactorMethods
}

func (e *env) row(userID string) *tfmodels.TwoFactor {
	e.t.Helper()
	var rows []tfmodels.TwoFactor
	if err := e.s.DB.Where(&tfmodels.TwoFactor{UserID: userID}).Find(&rows).Error; err != nil {
		e.t.Fatalf("query twoFactor: %v", err)
	}
	if len(rows) == 0 {
		return nil
	}
	return &rows[0]
}

func (e *env) user(id string) *models.User {
	e.t.Helper()
	var u models.User
	if err := e.s.DB.Where("id = ?", id).Take(&u).Error; err != nil {
		e.t.Fatalf("query user: %v", err)
	}
	return &u
}

func (e *env) verificationByPrefix(prefix string) []models.Verification {
	e.t.Helper()
	var rows []models.Verification
	if err := e.s.DB.Where("identifier LIKE ?", prefix+"%").Find(&rows).Error; err != nil {
		e.t.Fatalf("query verification: %v", err)
	}
	return rows
}
