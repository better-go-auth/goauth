package test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// otpInbox records the codes the plugin sends, keyed by recipient.
type otpInbox struct {
	mu   sync.Mutex
	last map[string]emailotpconfig.SendVerificationOTPData
	sent int
}

func (b *otpInbox) send(data emailotpconfig.SendVerificationOTPData, _ *http.Request) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last == nil {
		b.last = map[string]emailotpconfig.SendVerificationOTPData{}
	}
	b.last[strings.ToLower(data.Email)] = data
	b.sent++
	return nil
}

func (b *otpInbox) code(t *testing.T, email string) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.last[strings.ToLower(email)]
	if !ok {
		t.Fatalf("no OTP sent to %s", email)
	}
	return d.OTP
}

func (b *otpInbox) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sent
}

// newParityServer starts goauth with the email-otp plugin on the compat harness.
func newParityServer(t *testing.T, cfg emailotpconfig.EmailOTPConfig) (*compattest.Server, *otpInbox) {
	t.Helper()
	inbox := &otpInbox{}
	cfg.SendVerificationOTP = inbox.send
	disabled := false
	cfg.RateLimit.Enabled = &disabled
	s := compattest.NewServer(t,
		compattest.WithPlugin(emailotp.New(cfg)),
		compattest.WithConfig(func(c *config.AuthConfig) { c.BaseURL = "http://localhost:3000" }),
	)
	return s, inbox
}

func signUp(t *testing.T, s *compattest.Server, email string) string {
	t.Helper()
	res := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": "password1234", "name": "Ada"})
	if res.Status != http.StatusOK {
		t.Fatalf("sign-up: %d %s", res.Status, res.Body)
	}
	var body struct {
		Token string `json:"token"`
	}
	res.JSON(t, &body)
	return body.Token
}

// TestEmailOTPParity_StorageFormat checks the verification rows are interchangeable with better-auth:
// identifier "<type>-otp-<email>", value "<otp>:<attempts>", and "encrypted" = symmetricEncrypt(secret).
func TestEmailOTPParity_StorageFormat(t *testing.T) {
	s, inbox := newParityServer(t, emailotpconfig.EmailOTPConfig{StoreOTP: emailotpconfig.StoreOTPConfig{Mode: emailotpconfig.StoreOTPEncrypted}})
	email := "store@example.com"
	signUp(t, s, email)

	res := s.Post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": email, "type": "sign-in"})
	if res.Status != http.StatusOK {
		t.Fatalf("send: %d %s", res.Status, res.Body)
	}
	var row models.Verification
	if err := s.DB.Where("identifier = ?", "sign-in-otp-"+email).Take(&row).Error; err != nil {
		t.Fatalf("expected better-auth identifier sign-in-otp-<email>: %v", err)
	}
	stored, attempts, ok := strings.Cut(row.Value, ":")
	if !ok || attempts != "0" {
		t.Fatalf("expected <otp>:0 value, got %q", row.Value)
	}
	plain, err := authcrypto.SymmetricDecrypt(compattest.TestSecret, stored)
	if err != nil {
		t.Fatalf("encrypted OTP must be better-auth symmetricEncrypt output: %v", err)
	}
	if plain != inbox.code(t, email) {
		t.Fatalf("decrypted %q, sent %q", plain, inbox.code(t, email))
	}

	// a row written by better-auth (symmetricEncrypt) is accepted for sign-in
	if err := s.DB.Model(&models.Verification{}).Where("id = ?", row.ID).
		Update("value", mustEncrypt(t, "424242")+":0").Error; err != nil {
		t.Fatal(err)
	}
	res = s.Post(t, "/api/auth/sign-in/email-otp", map[string]any{"email": email, "otp": "424242"})
	if res.Status != http.StatusOK {
		t.Fatalf("sign-in with better-auth encrypted row: %d %s", res.Status, res.Body)
	}
}

func mustEncrypt(t *testing.T, v string) string {
	t.Helper()
	enc, err := authcrypto.SymmetricEncrypt(compattest.TestSecret, v)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// TestEmailOTPParity_ErrorsAndSignUp covers better-auth's codes/messages and the OTP sign-up shape.
func TestEmailOTPParity_ErrorsAndSignUp(t *testing.T) {
	s, inbox := newParityServer(t, emailotpconfig.EmailOTPConfig{})

	// check-verification-otp for an unknown user: 400 USER_NOT_FOUND
	res := s.Post(t, "/api/auth/email-otp/check-verification-otp", map[string]any{"email": "nobody@example.com", "otp": "123456", "type": "sign-in"})
	if res.Status != http.StatusBadRequest || !strings.Contains(string(res.Body), `"USER_NOT_FOUND"`) {
		t.Fatalf("check unknown user: %d %s", res.Status, res.Body)
	}

	// wrong code: 400 INVALID_OTP "Invalid OTP"
	email := "newbie@example.com"
	res = s.Post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": email, "type": "sign-in"})
	if res.Status != http.StatusOK {
		t.Fatalf("send: %d %s", res.Status, res.Body)
	}
	res = s.Post(t, "/api/auth/sign-in/email-otp", map[string]any{"email": email, "otp": "000000x"})
	if res.Status != http.StatusBadRequest || !strings.Contains(string(res.Body), `"message":"Invalid OTP"`) {
		t.Fatalf("invalid otp: %d %s", res.Status, res.Body)
	}

	// OTP sign-up: name "" when not given, email verified, and no credential account (better-auth createUser only)
	res = s.Post(t, "/api/auth/sign-in/email-otp", map[string]any{"email": email, "otp": inbox.code(t, email)})
	if res.Status != http.StatusOK {
		t.Fatalf("otp sign-up: %d %s", res.Status, res.Body)
	}
	var body struct {
		Token string `json:"token"`
		User  struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			EmailVerified bool   `json:"emailVerified"`
		} `json:"user"`
	}
	res.JSON(t, &body)
	if body.Token == "" || body.User.Name != "" || !body.User.EmailVerified {
		t.Fatalf("unexpected sign-up response: %s", res.Body)
	}
	if acc, err := s.Auth.Repositories().FindAccountByUserAndProvider(context.Background(), body.User.ID, models.ProvCredential); err == nil && acc != nil {
		t.Fatalf("OTP sign-up must not create a credential account, got %+v", acc)
	}

	// the session records the client IP / user agent (request context reaches plugin routes)
	var sess models.Session
	if err := s.DB.Where("user_id = ?", body.User.ID).Take(&sess).Error; err != nil {
		t.Fatal(err)
	}
	if sess.UserAgent == nil || *sess.UserAgent == "" {
		t.Fatalf("plugin sessions must store the user agent, got %+v", sess)
	}
}

// TestEmailOTPParity_ChangeEmail checks better-auth's change-email identifiers, {"success": true} bodies and
// the silent success for addresses that are already registered.
func TestEmailOTPParity_ChangeEmail(t *testing.T) {
	cfg := emailotpconfig.EmailOTPConfig{}
	cfg.ChangeEmail.Enabled = true
	s, inbox := newParityServer(t, cfg)
	// the harness client keeps the cookies of the last sign-up, so the acting user signs up last
	signUp(t, s, "taken@example.com")
	signUp(t, s, "old@example.com")
	auth := map[string]string{}

	// a registered target answers success but sends nothing (no account probing)
	before := inbox.count()
	res := s.Post(t, "/api/auth/email-otp/request-email-change", map[string]any{"newEmail": "taken@example.com"}, auth)
	if res.Status != http.StatusOK || !strings.Contains(string(res.Body), `"success":true`) {
		t.Fatalf("request for taken email: %d %s", res.Status, res.Body)
	}
	if inbox.count() != before {
		t.Fatal("no OTP may be sent to an already registered address")
	}

	// same email: EMAIL_IS_THE_SAME
	res = s.Post(t, "/api/auth/email-otp/request-email-change", map[string]any{"newEmail": "old@example.com"}, auth)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("same email: %d %s", res.Status, res.Body)
	}

	// real change: code stored under change-email-otp-<old>-<new>
	res = s.Post(t, "/api/auth/email-otp/request-email-change", map[string]any{"newEmail": "fresh@example.com"}, auth)
	if res.Status != http.StatusOK {
		t.Fatalf("request: %d %s", res.Status, res.Body)
	}
	var row models.Verification
	if err := s.DB.Where("identifier = ?", "change-email-otp-old@example.com-fresh@example.com").Take(&row).Error; err != nil {
		t.Fatalf("expected better-auth change-email identifier: %v", err)
	}
	res = s.Post(t, "/api/auth/email-otp/change-email", map[string]any{"newEmail": "fresh@example.com", "otp": inbox.code(t, "fresh@example.com")}, auth)
	if res.Status != http.StatusOK || !strings.Contains(string(res.Body), `"success":true`) {
		t.Fatalf("change-email: %d %s", res.Status, res.Body)
	}
	res = s.Get(t, "/api/auth/get-session", auth)
	if !strings.Contains(string(res.Body), `"email":"fresh@example.com"`) {
		t.Fatalf("session must show the new email: %s", res.Body)
	}
}
