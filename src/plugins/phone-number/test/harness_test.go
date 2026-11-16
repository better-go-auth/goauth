package test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	phonenumber "github.com/better-go-auth/goauth/src/plugins/phone-number"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// smsBox records the codes the plugin "sends".
type smsBox struct {
	mu     sync.Mutex
	codes  map[string]string
	resets map[string]string
	sent   int
	resent int
}

func newSMSBox() *smsBox {
	return &smsBox{codes: map[string]string{}, resets: map[string]string{}}
}

func (b *smsBox) send(data phoneconfig.OTPData, _ *http.Request) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.codes[data.PhoneNumber] = data.Code
	b.sent++
	return nil
}

func (b *smsBox) sendReset(data phoneconfig.OTPData, _ *http.Request) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resets[data.PhoneNumber] = data.Code
	b.resent++
	return nil
}

func (b *smsBox) code(t *testing.T, phone string) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.codes[phone]
	if c == "" {
		t.Fatalf("no SMS code sent to %s", phone)
	}
	return c
}

func (b *smsBox) resetCode(t *testing.T, phone string) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.resets[phone]
	if c == "" {
		t.Fatalf("no reset SMS sent to %s", phone)
	}
	return c
}

type harness struct {
	*compattest.Server
	sms    *smsBox
	plugin *phonenumber.Plugin
}

// newHarness starts the real goauth server with the phone-number plugin. SendOTP and SendPasswordResetOTP
// default to the SMS box unless cfg sets them; configure tweaks the AuthConfig.
func newHarness(t *testing.T, cfg phoneconfig.PhoneNumberConfig, configure ...func(*config.AuthConfig)) *harness {
	t.Helper()
	return startHarness(t, cfg, true, configure...)
}

// newHarnessNoSender starts the server without SMS senders (send-otp answers 501).
func newHarnessNoSender(t *testing.T, cfg phoneconfig.PhoneNumberConfig, configure ...func(*config.AuthConfig)) *harness {
	t.Helper()
	return startHarness(t, cfg, false, configure...)
}

func startHarness(t *testing.T, cfg phoneconfig.PhoneNumberConfig, withSender bool, configure ...func(*config.AuthConfig)) *harness {
	t.Helper()
	// Step 1: wire the SMS box as the default sender
	box := newSMSBox()
	if withSender && cfg.SendOTP == nil {
		cfg.SendOTP = box.send
	}
	if withSender && cfg.SendPasswordResetOTP == nil {
		cfg.SendPasswordResetOTP = box.sendReset
	}
	p := phonenumber.New(cfg)
	// Step 2: start the server with the compat defaults
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
	// Step 3: cookies are passed explicitly so several users can share one server
	s.Client.Jar = nil
	return &harness{Server: s, sms: box, plugin: p}
}

// errBody is better-auth's error shape.
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

func cookieBySuffix(r *compattest.Response, suffix string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if strings.HasSuffix(c.Name, suffix) {
			return c
		}
	}
	return nil
}

func withCookie(c string) map[string]string { return map[string]string{"Cookie": c} }

// verification returns the newest verification row for identifier (nil if none).
func (h *harness) verification(t *testing.T, identifier string) *models.Verification {
	t.Helper()
	v, err := h.Auth.Repositories().FindVerificationValue(context.Background(), identifier)
	if err != nil {
		return nil
	}
	return v
}

// signUpEmail creates a password user through core /sign-up/email and returns its cookies.
func (h *harness) signUpEmail(t *testing.T, email, password string) (userID, cookies string) {
	t.Helper()
	r := h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Phone User"})
	expectOK(t, r)
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(t, &body)
	return body.User.ID, cookieHeader(r)
}

// setPhone attaches a phone number to a user directly in the database.
func (h *harness) setPhone(t *testing.T, userID, phone string, verified bool) {
	t.Helper()
	if _, err := h.Auth.Repositories().UpdateUser(context.Background(), userID, map[string]interface{}{"PhoneNumber": &phone, "PhoneNumberVerified": verified}); err != nil {
		t.Fatalf("set phone: %v", err)
	}
}

// sendAndVerify runs send-otp + verify for phone and returns the verify response.
func (h *harness) sendAndVerify(t *testing.T, phone string, extra map[string]any, headers ...map[string]string) *compattest.Response {
	t.Helper()
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}))
	body := map[string]any{"phoneNumber": phone, "code": h.sms.code(t, phone)}
	for k, v := range extra {
		body[k] = v
	}
	return h.Post(t, "/api/auth/phone-number/verify", body, headers...)
}

// getSession calls /get-session with cookies and decodes the user.
func (h *harness) getSession(t *testing.T, cookies string) map[string]any {
	t.Helper()
	r := h.Get(t, "/api/auth/get-session", withCookie(cookies))
	expectOK(t, r)
	var body map[string]any
	r.JSON(t, &body)
	return body
}

func signUpConfig() phoneconfig.PhoneNumberConfig {
	return phoneconfig.PhoneNumberConfig{
		SignUpOnVerification: &phoneconfig.SignUpOnVerification{
			GetTempEmail: func(p string) string { return strings.TrimPrefix(p, "+") + "@phone.example.invalid" },
			GetTempName:  func(p string) string { return "User " + p },
		},
	}
}
