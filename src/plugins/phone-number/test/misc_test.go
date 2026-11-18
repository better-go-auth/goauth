package test

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
)

func TestRateLimitPhoneNumberPaths(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{}, func(c *config.AuthConfig) { c.RateLimit.Enabled = true })
	// Step 1: /phone-number/* allows 10 requests per 60s
	for i := 0; i < 10; i++ {
		expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+15550003000"}))
	}
	r := h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+15550003000"})
	if r.Status != http.StatusTooManyRequests {
		t.Fatalf("11th request status = %d (%s)", r.Status, r.Body)
	}
	if s, err := strconv.Atoi(r.Header.Get("X-Retry-After")); err != nil || s <= 0 || s > 60 {
		t.Fatalf("X-Retry-After = %q", r.Header.Get("X-Retry-After"))
	}
	if string(r.Body) != `{"message":"Too many requests. Please try again later."}` {
		t.Fatalf("body = %s", r.Body)
	}
	// Step 2: the counter is per path
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": "+1", "code": "1"}), http.StatusBadRequest, "OTP_NOT_FOUND")
	// Step 3: sign-in uses better-auth's /sign-in rule (3 per 10s)
	for i := 0; i < 3; i++ {
		expectError(t, signIn(h, t, "+1", "x"), http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD")
	}
	if r := signIn(h, t, "+1", "x"); r.Status != http.StatusTooManyRequests {
		t.Fatalf("4th sign-in status = %d", r.Status)
	}
}

func TestRateLimitDisabledByDefault(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	for i := 0; i < 15; i++ {
		expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+15550003001"}))
	}
}

func TestPhoneNumberIsUnique(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550004000"
	uid1, _ := h.signUpEmail(t, "u1@example.com", "password123")
	uid2, _ := h.signUpEmail(t, "u2@example.com", "password123")
	h.setPhone(t, uid1, phone, true)
	// the unique index rejects a second owner
	if _, err := h.Auth.Repositories().UpdateUser(context.Background(), uid2, map[string]interface{}{"PhoneNumber": &phone}); err == nil {
		t.Fatal("duplicate phone number accepted")
	}
	// users without a phone keep NULL, so many of them coexist
	h.signUpEmail(t, "u3@example.com", "password123")
	var n int64
	h.DB.Model(&models.User{}).Where("phone_number IS NULL").Count(&n)
	if n < 2 {
		t.Fatalf("users without phone = %d", n)
	}
}

// TestUserShapeWithoutPhone: the plugin is installed, so its fields are present (null), like better-auth.
func TestUserShapeWithoutPhone(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	_, cookies := h.signUpEmail(t, "nophone@example.com", "password123")
	u := h.getSession(t, cookies)["user"].(map[string]any)
	// better-auth returns the installed plugin's fields as null for users without a phone
	for _, k := range []string{"phoneNumber", "phoneNumberVerified"} {
		if v, ok := u[k]; !ok || v != nil {
			t.Fatalf("%s must be null for users without phone: %v", k, u)
		}
	}
}

func TestMalformedBodies(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	// required fields are validated before the handler runs
	for _, tc := range []struct {
		path string
		body map[string]any
	}{
		{"/api/auth/phone-number/send-otp", map[string]any{}},
		{"/api/auth/phone-number/verify", map[string]any{"phoneNumber": "+1"}},
		{"/api/auth/sign-in/phone-number", map[string]any{"phoneNumber": "+1"}},
		{"/api/auth/phone-number/reset-password", map[string]any{"phoneNumber": "+1", "otp": "1"}},
	} {
		r := h.Post(t, tc.path, tc.body)
		if r.Status < 400 || r.Status >= 500 {
			t.Fatalf("%s %v status = %d (%s)", tc.path, tc.body, r.Status, r.Body)
		}
	}
}

func TestOriginCheckWithCookies(t *testing.T) {
	h := newHarness(t, signUpConfig())
	_, cookies := h.signUpEmail(t, "origin@example.com", "password123")
	// a cookie-carrying request from an untrusted origin is rejected (better-auth originCheck)
	r := h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+15550005000"},
		map[string]string{"Cookie": cookies, "Origin": "https://evil.example.com"})
	if r.Status != http.StatusForbidden {
		t.Fatalf("status = %d (%s)", r.Status, r.Body)
	}
}
