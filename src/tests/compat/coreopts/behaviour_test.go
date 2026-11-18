package coreopts

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/better-go-auth/goauth/src/plugins/passkey"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// TestEmailOTPChangeEmailUsesSensitiveSession: /email-otp/request-email-change and /email-otp/change-email run
// behind better-auth's sensitiveSessionMiddleware, which ignores the cookie cache, so a revoked session that is
// still cached in session_data cannot change the email.
func TestEmailOTPChangeEmailUsesSensitiveSession(t *testing.T) {
	cfg := emailotpconfig.DefaultConfig()
	cfg.SendVerificationOTP = func(emailotpconfig.SendVerificationOTPData, *http.Request) error { return nil }
	cfg.ChangeEmail.Enabled = true
	yes := true
	s := compattest.NewServer(t, compattest.WithPlugin(emailotp.New(cfg)), compattest.WithConfig(func(c *config.AuthConfig) {
		c.Session.CookieCache = &config.CookieCache{Enabled: &yes}
	}))
	up := signUp(t, s, "change@example.com", nil)
	cookie := cookieHeader(up)
	if !strings.Contains(cookie, "better-auth.session_data=") {
		t.Fatalf("cookie cache expected: %s", cookie)
	}
	headers := map[string]string{"Cookie": cookie, "Origin": s.Origin}
	body := map[string]any{"newEmail": "new@example.com"}

	// Step 1: a live session may request the change
	if r := call(t, s, http.MethodPost, "/api/auth/email-otp/request-email-change", body, headers); r.Status != http.StatusOK {
		t.Fatalf("request-email-change: %d %s", r.Status, r.Body)
	}
	// Step 2: revoke the session; the cookie cache still describes it, so get-session keeps answering from it
	tok := setCookie(up, "better-auth.session_token").Value
	raw, _ := url.QueryUnescape(tok)
	token := raw[:strings.LastIndex(raw, ".")]
	if err := s.Auth.Sessions().Delete(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if got := sessionEmail(t, s, cookie); got != "change@example.com" {
		t.Fatalf("get-session should still answer from the cookie cache, got %q", got)
	}
	// Step 3: the sensitive endpoints read the session store and answer 401 UNAUTHORIZED
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/email-otp/request-email-change", body, headers), http.StatusUnauthorized, "UNAUTHORIZED")
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/email-otp/change-email", map[string]any{"newEmail": "new@example.com", "otp": "123456"}, headers), http.StatusUnauthorized, "UNAUTHORIZED")
	// Step 4: no session at all is 401 with better-auth's code as well
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/email-otp/request-email-change", body, map[string]string{"Origin": s.Origin}), http.StatusUnauthorized, "UNAUTHORIZED")
}

// TestPasskeyValidationBeforeSessionAndOriginMissing ports two better-auth passkey details: request validation
// runs before the session middleware (better-call), and verify-authentication without any origin answers
// 400 {"message": "origin missing"} without a code.
func TestPasskeyValidationBeforeSessionAndOriginMissing(t *testing.T) {
	s := compattest.NewServer(t, compattest.WithPlugin(passkey.New(pkconfig.PasskeyConfig{})))
	anon := map[string]string{"Origin": s.Origin}
	// Step 1: anonymous + invalid body → 400 VALIDATION_ERROR (was 401 before validation)
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/passkey/delete-passkey", map[string]any{"id": 5}, anon), http.StatusBadRequest, "VALIDATION_ERROR")
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/passkey/update-passkey", map[string]any{"id": "x"}, anon), http.StatusBadRequest, "VALIDATION_ERROR")
	// Step 2: anonymous + valid body → 401 UNAUTHORIZED
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/passkey/delete-passkey", map[string]any{"id": "x"}, anon), http.StatusUnauthorized, "UNAUTHORIZED")
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/passkey/update-passkey", map[string]any{"id": "x", "name": "n"}, anon), http.StatusUnauthorized, "UNAUTHORIZED")
	// Step 3: verify-authentication without an Origin header and without the origin option
	r := call(t, s, http.MethodPost, "/api/auth/passkey/verify-authentication", map[string]any{"response": map[string]any{}}, nil)
	if r.Status != http.StatusBadRequest || strings.TrimSpace(string(r.Body)) != `{"message":"origin missing"}` {
		t.Fatalf("origin missing: %d %s", r.Status, r.Body)
	}
}
