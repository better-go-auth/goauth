package main

import (
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

type userBody struct {
	ID                  string  `json:"id"`
	Email               string  `json:"email"`
	Name                string  `json:"name"`
	PhoneNumber         *string `json:"phoneNumber"`
	PhoneNumberVerified bool    `json:"phoneNumberVerified"`
}

type verifyBody struct {
	Status bool     `json:"status"`
	Token  *string  `json:"token"`
	User   userBody `json:"user"`
}

// wrongCode returns a code that differs from code.
func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

// TestPhoneSignUpAndPassword signs up by SMS, sets a password by SMS reset, then signs in with it.
func TestPhoneSignUpAndPassword(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	const phone = "+15550001234"

	// Step 1: send a verification code by SMS
	var sent struct {
		Message string `json:"message"`
	}
	c.MustOK(c.Post("/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}), &sent)
	code := outbox.Last("sms", phone)
	if sent.Message != "code sent" || len(code) != 6 {
		t.Fatalf("send-otp: %+v code=%q", sent, code)
	}

	// Step 2: verify it; the number is unknown, so SignUpOnVerification creates the user and signs them in
	if r := c.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("me without session: status %d, want 401", r.Status)
	}
	var verified verifyBody
	c.MustOK(c.Post("/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": code}), &verified)
	u := verified.User
	if !verified.Status || verified.Token == nil || u.PhoneNumber == nil || *u.PhoneNumber != phone ||
		!u.PhoneNumberVerified || u.Email != "15550001234@phone.example.com" || u.Name != phone {
		t.Fatalf("verify = %+v", verified)
	}

	// Step 3: the session cookie opens the protected route
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.UserID != u.ID {
		t.Fatalf("me = %+v", me.Body)
	}

	// Step 4: a user created by SMS has no password yet, so password sign-in fails
	b := c.Fork()
	if r := b.Post("/api/auth/sign-in/phone-number", map[string]any{"phoneNumber": phone, "password": "Password123!"}); r.Status != http.StatusUnauthorized || r.ErrorCode() != "INVALID_PHONE_NUMBER_OR_PASSWORD" {
		t.Fatalf("no password yet: %d %s", r.Status, r.Body)
	}

	// Step 5: set one with the SMS password reset (it creates the credential account)
	var status struct {
		Status bool `json:"status"`
	}
	b.MustOK(b.Post("/api/auth/phone-number/request-password-reset", map[string]any{"phoneNumber": phone}), &status)
	resetCode := outbox.Last("sms-reset", phone)
	if !status.Status || resetCode == "" {
		t.Fatalf("request-password-reset: %+v code=%q", status, resetCode)
	}
	b.MustOK(b.Post("/api/auth/phone-number/reset-password", map[string]any{"phoneNumber": phone, "otp": resetCode, "newPassword": "Password123!"}), &status)

	// Step 6: sign in with phone number + password
	var signIn struct {
		Token string   `json:"token"`
		User  userBody `json:"user"`
	}
	b.MustOK(b.Post("/api/auth/sign-in/phone-number", map[string]any{"phoneNumber": phone, "password": "Password123!"}), &signIn)
	if signIn.Token == "" || signIn.User.ID != u.ID {
		t.Fatalf("sign-in = %+v", signIn)
	}
	b.MustOK(b.Get("/api/example/me"), nil)

	// Step 7: a wrong password, and the reset code is single use
	if r := c.Fork().Post("/api/auth/sign-in/phone-number", map[string]any{"phoneNumber": phone, "password": "wrong-password"}); r.Status != http.StatusUnauthorized || r.ErrorCode() != "INVALID_PHONE_NUMBER_OR_PASSWORD" {
		t.Fatalf("wrong password: %d %s", r.Status, r.Body)
	}
	if r := b.Post("/api/auth/phone-number/reset-password", map[string]any{"phoneNumber": phone, "otp": resetCode, "newPassword": "Another123!"}); r.Status != http.StatusBadRequest || r.ErrorCode() != "OTP_NOT_FOUND" {
		t.Fatalf("reused reset code: %d %s", r.Status, r.Body)
	}
}

// TestAddPhoneToEmailAccount attaches a verified number to a signed-in email/password user.
func TestAddPhoneToEmailAccount(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	const phone = "+15550005678"

	// Step 1: an email/password user signs up (the session cookie is kept)
	var signUp struct {
		User userBody `json:"user"`
	}
	c.MustOK(c.SignUp("pat@example.com", "Password123!", "Pat"), &signUp)

	// Step 2: the phone number can't be set through /update-user...
	if r := c.Post("/api/auth/update-user", map[string]any{"phoneNumber": phone}); r.Status != http.StatusBadRequest || r.ErrorCode() != "PHONE_NUMBER_CANNOT_BE_UPDATED" {
		t.Fatalf("update-user phoneNumber: %d %s", r.Status, r.Body)
	}

	// Step 3: ...only by verifying it with updatePhoneNumber=true while signed in
	c.MustOK(c.Post("/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}), nil)
	var verified verifyBody
	c.MustOK(c.Post("/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": outbox.Last("sms", phone), "updatePhoneNumber": true}), &verified)
	if verified.User.ID != signUp.User.ID || verified.User.PhoneNumber == nil || *verified.User.PhoneNumber != phone || !verified.User.PhoneNumberVerified {
		t.Fatalf("verify updatePhoneNumber = %+v", verified)
	}

	// Step 4: the existing password now also works with the phone number
	b := c.Fork()
	b.MustOK(b.Post("/api/auth/sign-in/phone-number", map[string]any{"phoneNumber": phone, "password": "Password123!"}), nil)
	var me exkit.MeOutput
	b.MustOK(b.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "pat@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}
}

// TestPhoneErrors shows the code checks and the attempts limit.
func TestPhoneErrors(t *testing.T) {
	app, outbox, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	const phone = "+15550009999"

	// Step 1: PhoneNumberValidator rejects malformed numbers
	if r := c.Post("/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "555-1234"}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_PHONE_NUMBER" {
		t.Fatalf("bad number: %d %s", r.Status, r.Body)
	}

	// Step 2: verifying before a code was sent
	if r := c.Post("/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": "123456"}); r.Status != http.StatusBadRequest || r.ErrorCode() != "OTP_NOT_FOUND" {
		t.Fatalf("no code: %d %s", r.Status, r.Body)
	}

	// Step 3: wrong codes are 400 INVALID_OTP; after AllowedAttempts (3) the code is locked: 403 TOO_MANY_ATTEMPTS
	c.MustOK(c.Post("/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}), nil)
	code := outbox.Last("sms", phone)
	for i := 0; i < 3; i++ {
		if r := c.Post("/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": wrongCode(code)}); r.Status != http.StatusBadRequest || r.ErrorCode() != "INVALID_OTP" {
			t.Fatalf("attempt %d: %d %s", i+1, r.Status, r.Body)
		}
	}
	if r := c.Post("/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": code}); r.Status != http.StatusForbidden || r.ErrorCode() != "TOO_MANY_ATTEMPTS" {
		t.Fatalf("locked out: %d %s", r.Status, r.Body)
	}

	// Step 4: a fresh code works again
	c.MustOK(c.Post("/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}), nil)
	c.MustOK(c.Post("/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": outbox.Last("sms", phone)}), nil)

	// Step 5: unknown numbers get {"status": true} from request-password-reset but no SMS
	c.MustOK(c.Post("/api/auth/phone-number/request-password-reset", map[string]any{"phoneNumber": "+15550000000"}), nil)
	if outbox.Last("sms-reset", "+15550000000") != "" {
		t.Fatal("unknown number must not get a reset code")
	}
}
