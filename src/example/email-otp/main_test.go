package main

import (
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

type userBody struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"emailVerified"`
}

// wrongCode returns a code that differs from code.
func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

// TestSignInWithOTP signs a new user up and in with a code, then calls the protected route.
func TestSignInWithOTP(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	const email = "otp-user@example.com"

	// Step 1: ask for a sign-in code (unknown addresses get one too: signing in creates the user)
	var sent struct {
		Success bool `json:"success"`
	}
	c.MustOK(c.Post("/api/auth/email-otp/send-verification-otp", map[string]any{"email": email, "type": "sign-in"}), &sent)
	code := outbox.Last("sign-in", email)
	if !sent.Success || len(code) != 6 {
		t.Fatalf("success=%v code=%q", sent.Success, code)
	}

	// Step 2: check-verification-otp only works for registered users, so it can't be used here
	if r := c.Post("/api/auth/email-otp/check-verification-otp", map[string]any{"email": email, "type": "sign-in", "otp": code}); r.Status != http.StatusBadRequest || r.ErrorCode() != "USER_NOT_FOUND" {
		t.Fatalf("check unknown user: %d %s", r.Status, r.Body)
	}

	// Step 3: sign in with the code; the user is created with a verified email and the session cookie is set
	if r := c.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me without session: status %d, want 401", r.Status)
	}
	var signIn struct {
		Token string   `json:"token"`
		User  userBody `json:"user"`
	}
	c.MustOK(c.Post("/api/auth/sign-in/email-otp", map[string]any{"email": email, "otp": code, "name": "Otto"}), &signIn)
	if signIn.Token == "" || signIn.User.Name != "Otto" || !signIn.User.EmailVerified {
		t.Fatalf("sign-in = %+v", signIn)
	}

	// Step 4: the session cookie opens the protected route
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.Email != email || me.Body.UserID != signIn.User.ID {
		t.Fatalf("me = %+v", me.Body)
	}

	// Step 5: a code is single use
	if r := c.Fork().Post("/api/auth/sign-in/email-otp", map[string]any{"email": email, "otp": code}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_OTP" {
		t.Fatalf("reused code: %d %s", r.Status, r.Body)
	}
}

// TestEmailVerificationOTP verifies the address of an email/password user with a code.
func TestEmailVerificationOTP(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	const email = "verify-me@example.com"

	// Step 1: sign up with email and password; SendVerificationOnSignUp emails an "email-verification" code
	var signUp struct {
		User userBody `json:"user"`
	}
	c.MustOK(c.SignUp(email, "Password123!", "Vera"), &signUp)
	if signUp.User.EmailVerified {
		t.Fatal("email should not be verified yet")
	}
	code := outbox.Last("email-verification", email)
	if code == "" {
		t.Fatal("no verification code was sent on sign-up")
	}

	// Step 2: a wrong code is rejected
	if r := c.Post("/api/auth/email-otp/verify-email", map[string]any{"email": email, "otp": wrongCode(code)}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_OTP" {
		t.Fatalf("wrong code: %d %s", r.Status, r.Body)
	}

	// Step 3: the right code marks the email verified
	var verified struct {
		Status bool     `json:"status"`
		Token  *string  `json:"token"`
		User   userBody `json:"user"`
	}
	c.MustOK(c.Post("/api/auth/email-otp/verify-email", map[string]any{"email": email, "otp": code}), &verified)
	if !verified.Status || !verified.User.EmailVerified {
		t.Fatalf("verify-email = %+v", verified)
	}

	// Step 4: a new code can be requested later (e.g. "resend"); it replaces the previous one
	c.MustOK(c.Post("/api/auth/email-otp/send-verification-otp", map[string]any{"email": email, "type": "email-verification"}), nil)
	if outbox.Last("email-verification", email) == "" {
		t.Fatal("resend: no code")
	}
}

// TestResetPasswordWithOTP resets a forgotten password with a code.
func TestResetPasswordWithOTP(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	const email = "forgetful@example.com"
	c.MustOK(c.SignUp(email, "Password123!", "Fred"), nil)

	// Step 1: request a reset code (unknown addresses also get {"success": true}, but no email)
	c.MustOK(c.Post("/api/auth/email-otp/request-password-reset", map[string]any{"email": email}), nil)
	code := outbox.Last("forget-password", email)
	if code == "" {
		t.Fatal("no reset code was sent")
	}
	c.MustOK(c.Post("/api/auth/email-otp/request-password-reset", map[string]any{"email": "nobody@example.com"}), nil)
	if outbox.Last("forget-password", "nobody@example.com") != "" {
		t.Fatal("unknown address must not get a code")
	}

	// Step 2: a page can check the code before asking for the new password (it is not used up)
	c.MustOK(c.Post("/api/auth/email-otp/check-verification-otp", map[string]any{"email": email, "type": "forget-password", "otp": code}), nil)

	// Step 3: the new password must satisfy the length policy
	if r := c.Post("/api/auth/email-otp/reset-password", map[string]any{"email": email, "otp": code, "password": "short"}); r.Status != http.StatusBadRequest || r.ErrorCode() != "PASSWORD_TOO_SHORT" {
		t.Fatalf("short password: %d %s", r.Status, r.Body)
	}

	// Step 4: reset the password with the code
	var reset struct {
		Status bool `json:"status"`
	}
	c.MustOK(c.Post("/api/auth/email-otp/reset-password", map[string]any{"email": email, "otp": code, "password": "NewPassword456!"}), &reset)
	if !reset.Status {
		t.Fatal("reset-password: status false")
	}

	// Step 5: the old password stops working, the new one signs in
	b := c.Fork()
	if r := b.SignIn(email, "Password123!"); r.Status != http.StatusUnauthorized {
		t.Fatalf("old password: %d %s", r.Status, r.Body)
	}
	b.MustOK(b.SignIn(email, "NewPassword456!"), nil)
	b.MustOK(b.Get("/api/example/me"), nil)
}

// TestWrongOTPAttempts shows the error codes for wrong codes and the attempts limit.
func TestWrongOTPAttempts(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	const email = "guesser@example.com"
	c.MustOK(c.Post("/api/auth/email-otp/send-verification-otp", map[string]any{"email": email, "type": "sign-in"}), nil)
	code := outbox.Last("sign-in", email)
	bad := wrongCode(code)

	// Step 1: each wrong code is 400 INVALID_OTP and counts as an attempt (AllowedAttempts = 3)
	for i := 0; i < 3; i++ {
		if r := c.Post("/api/auth/sign-in/email-otp", map[string]any{"email": email, "otp": bad}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_OTP" {
			t.Fatalf("attempt %d: %d %s", i+1, r.Status, r.Body)
		}
	}

	// Step 2: after that the code is burnt: 403 TOO_MANY_ATTEMPTS even with the right code
	if r := c.Post("/api/auth/sign-in/email-otp", map[string]any{"email": email, "otp": code}); r.Status != http.StatusForbidden || r.ErrorCode() != "TOO_MANY_ATTEMPTS" {
		t.Fatalf("locked out: %d %s", r.Status, r.Body)
	}

	// Step 3: the code is deleted, so it stays INVALID_OTP until a new one is requested
	if r := c.Post("/api/auth/sign-in/email-otp", map[string]any{"email": email, "otp": code}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_OTP" {
		t.Fatalf("after lockout: %d %s", r.Status, r.Body)
	}
	c.MustOK(c.Post("/api/auth/email-otp/send-verification-otp", map[string]any{"email": email, "type": "sign-in"}), nil)
	c.MustOK(c.Post("/api/auth/sign-in/email-otp", map[string]any{"email": email, "otp": outbox.Last("sign-in", email)}), nil)

	// Step 4: a malformed address is rejected before anything is sent
	if r := c.Post("/api/auth/email-otp/send-verification-otp", map[string]any{"email": "not-an-email", "type": "sign-in"}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_EMAIL" {
		t.Fatalf("bad email: %d %s", r.Status, r.Body)
	}
}
