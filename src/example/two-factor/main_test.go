package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/plugins/two-factor/services"
)

const (
	email    = "alice@example.com"
	password = "Password123!"
)

// challenge is the sign-in answer when the second factor is still missing.
type challenge struct {
	TwoFactorRedirect bool     `json:"twoFactorRedirect"`
	TwoFactorMethods  []string `json:"twoFactorMethods"`
	Token             string   `json:"token"`
}

// totp is what an authenticator app shows for secret right now.
func totp(secret string) string {
	return services.TOTP(secret, time.Now(), 30*time.Second, 6)
}

// mustChallenge signs in with the password and checks that 2FA is asked for (no session yet).
func mustChallenge(t *testing.T, c *exkit.Client) challenge {
	t.Helper()
	var ch challenge
	r := c.MustOK(c.SignIn(email, password), &ch)
	if !ch.TwoFactorRedirect || ch.Token != "" {
		t.Fatalf("expected a two-factor challenge, got %s", r.Body)
	}
	if r.Cookie("better-auth.two_factor") == nil {
		t.Fatal("the challenge should set the two_factor cookie")
	}
	if r := c.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me before the second factor: status %d, want 401", r.Status)
	}
	return ch
}

// mustBeAlice checks that the client has a session for alice.
func mustBeAlice(t *testing.T, c *exkit.Client) {
	t.Helper()
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.Email != email {
		t.Fatalf("me = %+v", me.Body)
	}
}

func TestTwoFactorFlow(t *testing.T) {
	outbox := &exkit.Outbox{}
	app, err := newApp("", outbox)
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: sign up; 2FA is off, so password sign-in alone gives a session
	c.MustOK(c.SignUp(email, password, "Alice"), nil)
	mustBeAlice(t, c)

	// Step 2: enable 2FA (password required): returns the TOTP URI for the QR code and 10 backup codes
	var enabled struct {
		TotpURI     string   `json:"totpURI"`
		BackupCodes []string `json:"backupCodes"`
	}
	c.MustOK(c.Post("/api/auth/two-factor/enable", map[string]any{"password": password}), &enabled)
	if !strings.HasPrefix(enabled.TotpURI, "otpauth://totp/GoAuth%20Example:alice%40example.com?") || len(enabled.BackupCodes) != 10 {
		t.Fatalf("enable = %+v", enabled)
	}
	secret, err := services.ParseTOTPURI(enabled.TotpURI)
	if err != nil {
		t.Fatal(err)
	}

	// Step 3: the URI can be fetched again later (e.g. to show the QR code once more)
	var uri struct {
		TotpURI string `json:"totpURI"`
	}
	c.MustOK(c.Post("/api/auth/two-factor/get-totp-uri", map[string]any{"password": password}), &uri)
	if got, _ := services.ParseTOTPURI(uri.TotpURI); got != secret {
		t.Fatal("get-totp-uri should return the same secret")
	}

	// Step 4: 2FA is only switched on once the first code from the app is verified
	var session struct {
		User struct {
			TwoFactorEnabled bool `json:"twoFactorEnabled"`
		} `json:"user"`
	}
	c.MustOK(c.Get("/api/auth/get-session"), &session)
	if session.User.TwoFactorEnabled {
		t.Fatal("2FA must stay off until the first TOTP check")
	}
	c.MustOK(c.Post("/api/auth/two-factor/verify-totp", map[string]any{"code": totp(secret)}), nil)
	c.MustOK(c.Get("/api/auth/get-session"), &session)
	if !session.User.TwoFactorEnabled {
		t.Fatal("2FA should be on after verify-totp")
	}
	c.MustOK(c.Post("/api/auth/sign-out", map[string]any{}), nil)

	// Step 5: a new browser signs in: the password is not enough any more
	b := c.Fork()
	ch := mustChallenge(t, b)
	if strings.Join(ch.TwoFactorMethods, ",") != "totp,otp" {
		t.Fatalf("methods = %v", ch.TwoFactorMethods)
	}

	// Step 6: a wrong TOTP code is refused, the right one creates the session
	if r := b.Post("/api/auth/two-factor/verify-totp", map[string]any{"code": "000000x"}); r.Status != http.StatusUnauthorized || r.ErrorCode() != "INVALID_CODE" {
		t.Fatalf("wrong code: %d %s", r.Status, r.Body)
	}
	b.MustOK(b.Post("/api/auth/two-factor/verify-totp", map[string]any{"code": totp(secret)}), nil)
	mustBeAlice(t, b)

	// Step 7: without the two_factor cookie of a pending sign-in there is nothing to verify
	if r := c.Fork().Post("/api/auth/two-factor/verify-totp", map[string]any{"code": totp(secret)}); r.Status != http.StatusUnauthorized || r.ErrorCode() != "INVALID_TWO_FACTOR_COOKIE" {
		t.Fatalf("verify without challenge: %d %s", r.Status, r.Body)
	}

	// Step 8: the email method: send-otp hands a code to SendOTP, verify-otp checks it; trustDevice
	// remembers this browser for 30 days
	d := c.Fork()
	mustChallenge(t, d)
	d.MustOK(d.Post("/api/auth/two-factor/send-otp", map[string]any{}), nil)
	otp := outbox.Last("two-factor-otp", email)
	if len(otp) != 6 {
		t.Fatalf("otp = %q", otp)
	}
	r := d.MustOK(d.Post("/api/auth/two-factor/verify-otp", map[string]any{"code": otp, "trustDevice": true}), nil)
	if r.Cookie("better-auth.trust_device") == nil {
		t.Fatal("trustDevice should set the trust_device cookie")
	}
	mustBeAlice(t, d)

	// Step 9: the trusted browser signs in with the password alone
	d.MustOK(d.Post("/api/auth/sign-out", map[string]any{}), nil)
	var direct challenge
	d.MustOK(d.SignIn(email, password), &direct)
	if direct.TwoFactorRedirect || direct.Token == "" {
		t.Fatalf("a trusted device should skip 2FA: %+v", direct)
	}
	mustBeAlice(t, d)

	// Step 10: lost phone: a backup code works once
	e := c.Fork()
	mustChallenge(t, e)
	e.MustOK(e.Post("/api/auth/two-factor/verify-backup-code", map[string]any{"code": enabled.BackupCodes[0]}), nil)
	mustBeAlice(t, e)
	f := c.Fork()
	mustChallenge(t, f)
	if r := f.Post("/api/auth/two-factor/verify-backup-code", map[string]any{"code": enabled.BackupCodes[0]}); r.Status != http.StatusUnauthorized || r.ErrorCode() != "INVALID_BACKUP_CODE" {
		t.Fatalf("reused backup code: %d %s", r.Status, r.Body)
	}

	// Step 11: signed in, the user can replace the backup codes (the old ones stop working)
	var regenerated struct {
		Status      bool     `json:"status"`
		BackupCodes []string `json:"backupCodes"`
	}
	e.MustOK(e.Post("/api/auth/two-factor/generate-backup-codes", map[string]any{"password": password}), &regenerated)
	if !regenerated.Status || len(regenerated.BackupCodes) != 10 {
		t.Fatalf("generate-backup-codes = %+v", regenerated)
	}
	if r := f.Post("/api/auth/two-factor/verify-backup-code", map[string]any{"code": enabled.BackupCodes[1]}); r.ErrorCode() != "INVALID_BACKUP_CODE" {
		t.Fatalf("old backup code after regeneration: %d %s", r.Status, r.Body)
	}
	f.MustOK(f.Post("/api/auth/two-factor/verify-backup-code", map[string]any{"code": regenerated.BackupCodes[0]}), nil)
	mustBeAlice(t, f)

	// Step 12: disable 2FA (password required); sign-in no longer asks for a second factor
	if r := e.Post("/api/auth/two-factor/disable", map[string]any{"password": "wrong-password"}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_PASSWORD" {
		t.Fatalf("disable with a wrong password: %d %s", r.Status, r.Body)
	}
	e.MustOK(e.Post("/api/auth/two-factor/disable", map[string]any{"password": password}), nil)
	g := c.Fork()
	var plain challenge
	g.MustOK(g.SignIn(email, password), &plain)
	if plain.TwoFactorRedirect || plain.Token == "" {
		t.Fatalf("sign-in after disable should not be challenged: %+v", plain)
	}
	mustBeAlice(t, g)
}
