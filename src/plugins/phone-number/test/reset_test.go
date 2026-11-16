package test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	"github.com/better-go-auth/goauth/src/plugins/phone-number/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

type responseT = compattest.Response

var errBlocked = pluginkit.NewError(http.StatusForbidden, "BLOCKED", "blocked")

func requestReset(h *harness, t *testing.T, phone string) {
	t.Helper()
	r := h.Post(t, "/api/auth/phone-number/request-password-reset", map[string]any{"phoneNumber": phone})
	expectOK(t, r)
	if strings.TrimSpace(string(r.Body)) != `{"status":true}` {
		t.Fatalf("body = %s", r.Body)
	}
}

func resetPassword(h *harness, t *testing.T, phone, otp, password string) *responseT {
	t.Helper()
	return h.Post(t, "/api/auth/phone-number/reset-password", map[string]any{"phoneNumber": phone, "otp": otp, "newPassword": password})
}

func TestRequestPasswordResetStorage(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	// Step 1: unknown numbers get {status:true} and a stored code but no SMS
	requestReset(h, t, "+15550002000")
	if v := h.verification(t, "+15550002000"+services.PasswordResetSuffix); v == nil || !strings.HasSuffix(v.Value, ":0") {
		t.Fatalf("reset code not stored: %+v", v)
	}
	if h.sms.resent != 0 {
		t.Fatal("unknown numbers must not receive an SMS")
	}
	// Step 2: registered numbers receive the code; stored as "<phone>-request-password-reset" = "code:0"
	phone := "+15550002001"
	h.phoneUser(t, "reset@example.com", "password123", phone, true)
	requestReset(h, t, phone)
	code := h.sms.resetCode(t, phone)
	v := h.verification(t, phone+"-request-password-reset")
	if v == nil || v.Value != code+":0" {
		t.Fatalf("stored = %+v, want %q", v, code+":0")
	}
	if d := time.Until(v.ExpiresAt); d < 290*time.Second || d > 301*time.Second {
		t.Fatalf("expires in %v", d)
	}
}

func TestResetPasswordUpdatesCredential(t *testing.T) {
	var resetFor []string
	h := newHarness(t, phoneconfig.PhoneNumberConfig{}, func(c *config.AuthConfig) {
		c.EmailAndPassword.OnPasswordReset = func(d config.PasswordResetData, _ *http.Request) error {
			resetFor = append(resetFor, d.User.ID)
			return nil
		}
	})
	phone := "+15550002002"
	uid := h.phoneUser(t, "reset2@example.com", "password123", phone, true)
	requestReset(h, t, phone)
	code := h.sms.resetCode(t, phone)

	// Step 1: password policy is checked after the code
	expectError(t, resetPassword(h, t, phone, code, "short"), http.StatusBadRequest, "PASSWORD_TOO_SHORT")
	expectError(t, resetPassword(h, t, phone, code, strings.Repeat("x", 129)), http.StatusBadRequest, "PASSWORD_TOO_LONG")
	// Step 2: correct code → new password works, old one does not
	r := resetPassword(h, t, phone, code, "brand-new-pass")
	expectOK(t, r)
	if strings.TrimSpace(string(r.Body)) != `{"status":true}` {
		t.Fatalf("body = %s", r.Body)
	}
	expectOK(t, signIn(h, t, phone, "brand-new-pass"))
	expectError(t, signIn(h, t, phone, "password123"), http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD")
	// Step 3: code is single use; callback ran once; sessions survive by default
	expectError(t, resetPassword(h, t, phone, code, "another-pass1"), http.StatusBadRequest, "OTP_NOT_FOUND")
	if len(resetFor) != 1 || resetFor[0] != uid {
		t.Fatalf("OnPasswordReset calls = %v", resetFor)
	}
	var accounts int64
	h.DB.Model(&models.Account{}).Where("user_id = ?", uid).Count(&accounts)
	if accounts != 1 {
		t.Fatalf("accounts = %d, want 1", accounts)
	}
}

func TestResetPasswordCreatesCredentialAccount(t *testing.T) {
	h := newHarness(t, signUpConfig())
	phone := "+15550002003"
	// Step 1: a phone-only user has no password
	expectOK(t, h.sendAndVerify(t, phone, nil))
	expectError(t, signIn(h, t, phone, "fresh-password"), http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD")
	// Step 2: the reset creates the credential account
	requestReset(h, t, phone)
	expectOK(t, resetPassword(h, t, phone, h.sms.resetCode(t, phone), "fresh-password"))
	u, err := h.Auth.Repositories().FindUserByPhoneNumber(context.Background(), phone)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := h.Auth.Repositories().FindAccountByUserAndProvider(context.Background(), u.ID, models.ProvCredential)
	if err != nil || acc.AccountID != u.ID || acc.Password == nil {
		t.Fatalf("credential account = %+v, err %v", acc, err)
	}
	expectOK(t, signIn(h, t, phone, "fresh-password"))
}

func TestResetPasswordAttemptsAndErrors(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550002004"
	h.phoneUser(t, "reset4@example.com", "password123", phone, true)

	// Step 1: no code requested
	expectError(t, resetPassword(h, t, phone, "123456", "new-password"), http.StatusBadRequest, "OTP_NOT_FOUND")
	// Step 2: wrong codes count attempts; the 4th is locked out and the code deleted
	requestReset(h, t, phone)
	code := h.sms.resetCode(t, phone)
	for i := 0; i < 3; i++ {
		expectError(t, resetPassword(h, t, phone, "bad", "new-password"), http.StatusBadRequest, "INVALID_OTP")
	}
	if v := h.verification(t, phone+services.PasswordResetSuffix); v == nil || v.Value != code+":3" {
		t.Fatalf("value = %+v", v)
	}
	expectError(t, resetPassword(h, t, phone, code, "new-password"), http.StatusForbidden, "TOO_MANY_ATTEMPTS")
	if h.verification(t, phone+services.PasswordResetSuffix) != nil {
		t.Fatal("code must be deleted on lockout")
	}
	// Step 3: expired code
	requestReset(h, t, phone)
	v := h.verification(t, phone+services.PasswordResetSuffix)
	v.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := h.Auth.Repositories().UpsertVerificationValue(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	expectError(t, resetPassword(h, t, phone, h.sms.resetCode(t, phone), "new-password"), http.StatusBadRequest, "OTP_EXPIRED")
	// Step 4: a code for an unregistered number → UNEXPECTED_ERROR (400)
	requestReset(h, t, "+15550002999")
	stored := h.verification(t, "+15550002999"+services.PasswordResetSuffix)
	otp, _, _ := strings.Cut(stored.Value, ":")
	expectError(t, resetPassword(h, t, "+15550002999", otp, "new-password"), http.StatusBadRequest, "UNEXPECTED_ERROR")
	// Step 5: the verify code and the reset code are independent
	_ = h.Auth.Repositories().DeleteVerificationByIdentifier(context.Background(), phone+services.PasswordResetSuffix)
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}))
	expectError(t, resetPassword(h, t, phone, h.sms.code(t, phone), "new-password"), http.StatusBadRequest, "OTP_NOT_FOUND")
}

func TestResetPasswordRevokesSessions(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{}, func(c *config.AuthConfig) {
		c.EmailAndPassword.RevokeSessionsOnPasswordReset = true
	})
	phone := "+15550002005"
	h.phoneUser(t, "revoke@example.com", "password123", phone, true)
	r := signIn(h, t, phone, "password123")
	expectOK(t, r)
	cookies := cookieHeader(r)
	if h.getSession(t, cookies)["user"] == nil {
		t.Fatal("session should be valid before the reset")
	}
	requestReset(h, t, phone)
	expectOK(t, resetPassword(h, t, phone, h.sms.resetCode(t, phone), "after-reset-pass"))
	// the session cookie no longer resolves (get-session answers null)
	gr := h.Get(t, "/api/auth/get-session", withCookie(cookies))
	if gr.Status == http.StatusOK && strings.TrimSpace(string(gr.Body)) != "null" {
		t.Fatalf("session survived the reset: %s", gr.Body)
	}
}

func TestResetPasswordKeepsSessionsByDefault(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550002006"
	h.phoneUser(t, "keep@example.com", "password123", phone, true)
	r := signIn(h, t, phone, "password123")
	cookies := cookieHeader(r)
	requestReset(h, t, phone)
	expectOK(t, resetPassword(h, t, phone, h.sms.resetCode(t, phone), "after-reset-pass"))
	if h.getSession(t, cookies)["user"] == nil {
		t.Fatal("session must survive without RevokeSessionsOnPasswordReset")
	}
}
