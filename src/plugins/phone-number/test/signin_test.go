package test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
)

// phoneUser creates an email/password user owning phone (verified or not) and returns its id.
func (h *harness) phoneUser(t *testing.T, email, password, phone string, verified bool) string {
	t.Helper()
	uid, _ := h.signUpEmail(t, email, password)
	h.setPhone(t, uid, phone, verified)
	return uid
}

func signIn(h *harness, t *testing.T, phone, password string, extra ...map[string]any) *responseT {
	t.Helper()
	body := map[string]any{"phoneNumber": phone, "password": password}
	for _, e := range extra {
		for k, v := range e {
			body[k] = v
		}
	}
	return h.Post(t, "/api/auth/sign-in/phone-number", body)
}

func TestSignInPhoneNumber(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550001001"
	uid := h.phoneUser(t, "signin@example.com", "password123", phone, true)

	// Step 1: correct credentials → {token, user} with the phone fields and a persistent session cookie
	r := signIn(h, t, phone, "password123")
	expectOK(t, r)
	var body map[string]any
	r.JSON(t, &body)
	if len(body) != 2 {
		t.Fatalf("body must be exactly {token, user}: %s", r.Body)
	}
	tok, _ := body["token"].(string)
	user, _ := body["user"].(map[string]any)
	if tok == "" || user["id"] != uid || user["phoneNumber"] != phone || user["phoneNumberVerified"] != true {
		t.Fatalf("body = %s", r.Body)
	}
	c := cookieBySuffix(r, "session_token")
	if c == nil || c.MaxAge <= 0 {
		t.Fatalf("session cookie must persist: %+v", c)
	}
	if cookieBySuffix(r, "dont_remember") != nil {
		t.Fatal("dont_remember set without rememberMe=false")
	}
	if u := h.getSession(t, cookieHeader(r))["user"].(map[string]any); u["id"] != uid {
		t.Fatalf("get-session = %v", u)
	}
	// Step 2: session metadata like core sign-in
	var sess models.Session
	if err := h.DB.Where("user_id = ?", uid).Order("created_at desc").First(&sess).Error; err != nil {
		t.Fatal(err)
	}
}

func TestSignInPhoneNumberErrors(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550001002"
	h.phoneUser(t, "signin-err@example.com", "password123", phone, true)

	// wrong password
	expectError(t, signIn(h, t, phone, "wrong-password"), http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD")
	// unknown phone
	expectError(t, signIn(h, t, "+19999999999", "password123"), http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD")
	// message matches better-auth
	r := signIn(h, t, phone, "nope")
	var e errBody
	r.JSON(t, &e)
	if e.Message != "Invalid phone number or password" {
		t.Fatalf("message = %q", e.Message)
	}
}

func TestSignInPhoneOnlyUserWithoutPassword(t *testing.T) {
	h := newHarness(t, signUpConfig())
	phone := "+15550001003"
	// a phone-only user (created by verify) has no credential account
	expectOK(t, h.sendAndVerify(t, phone, nil))
	expectError(t, signIn(h, t, phone, "password123"), http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD")
}

func TestSignInCredentialAccountWithoutPassword(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550001009"
	uid := h.phoneUser(t, "nopass@example.com", "password123", phone, true)
	// blank out the stored hash → better-auth's 401 UNEXPECTED_ERROR
	if err := h.DB.Model(&models.Account{}).Where("user_id = ?", uid).Update("password", nil).Error; err != nil {
		t.Fatal(err)
	}
	expectError(t, signIn(h, t, phone, "password123"), http.StatusUnauthorized, "UNEXPECTED_ERROR")
}

func TestSignInRememberMeFalse(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550001004"
	h.phoneUser(t, "remember@example.com", "password123", phone, true)
	r := signIn(h, t, phone, "password123", map[string]any{"rememberMe": false})
	expectOK(t, r)
	c := cookieBySuffix(r, "session_token")
	if c == nil {
		t.Fatal("no session cookie")
	}
	if c.MaxAge != 0 || !c.Expires.IsZero() {
		t.Fatalf("rememberMe=false must set a browser-session cookie: %+v", c)
	}
	if cookieBySuffix(r, "dont_remember") == nil {
		t.Fatal("dont_remember cookie missing")
	}
}

func TestSignInRequireVerification(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{RequireVerification: true})
	phone := "+15550001005"
	h.phoneUser(t, "unverified@example.com", "password123", phone, false)

	// Step 1: unverified number → 401 PHONE_NUMBER_NOT_VERIFIED and an SMS code
	expectError(t, signIn(h, t, phone, "password123"), http.StatusUnauthorized, "PHONE_NUMBER_NOT_VERIFIED")
	code := h.sms.code(t, phone)
	// better-auth stores this code without the ":attempts" suffix
	if v := h.verification(t, phone); v == nil || v.Value != code {
		t.Fatalf("stored value = %+v, want %q", v, code)
	}
	// the check happens before the password check
	expectError(t, signIn(h, t, phone, "wrong"), http.StatusUnauthorized, "PHONE_NUMBER_NOT_VERIFIED")
	code = h.sms.code(t, phone)

	// Step 2: a wrong code still counts attempts from the suffix-less value
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": "x", "disableSession": true}), http.StatusBadRequest, "INVALID_OTP")
	if v := h.verification(t, phone); v == nil || v.Value != code+":1" {
		t.Fatalf("value after wrong code = %+v", v)
	}
	// Step 3: verifying the number unlocks password sign-in
	expectOK(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": code, "disableSession": true}))
	expectOK(t, signIn(h, t, phone, "password123"))
}

func TestSignInRequireVerificationWithoutSender(t *testing.T) {
	h := newHarnessNoSender(t, phoneconfig.PhoneNumberConfig{RequireVerification: true})
	phone := "+15550001006"
	h.phoneUser(t, "nosender@example.com", "password123", phone, false)
	expectError(t, signIn(h, t, phone, "password123"), http.StatusUnauthorized, "PHONE_NUMBER_NOT_VERIFIED")
	if h.verification(t, phone) == nil {
		t.Fatal("code must be stored even without a sender")
	}
}

func TestSignInTwoFactorInterceptor(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550001007"
	uid := h.phoneUser(t, "2fa@example.com", "password123", phone, true)

	// Step 1: a fake two-factor plugin replaces the sign-in response
	var events []plugins.SignInEvent
	h.Auth.Hooks().OnAfterSignIn(func(ctx context.Context, ev plugins.SignInEvent) (*plugins.SignInChallenge, error) {
		events = append(events, ev)
		if ev.Path != "/sign-in/phone-number" {
			return nil, nil
		}
		_ = h.Auth.Sessions().Delete(ctx, ev.Session.Session.Token)
		return &plugins.SignInChallenge{
			Body:    map[string]any{"twoFactorRedirect": true, "twoFactorMethods": []string{"totp"}},
			Cookies: []http.Cookie{{Name: "better-auth.two_factor", Value: "signed", Path: "/", HttpOnly: true}},
		}, nil
	})

	// Step 2: the challenge body and cookies are written instead of the session
	r := signIn(h, t, phone, "password123", map[string]any{"rememberMe": false})
	expectOK(t, r)
	if !strings.Contains(string(r.Body), `"twoFactorRedirect":true`) || strings.Contains(string(r.Body), `"token"`) {
		t.Fatalf("body = %s", r.Body)
	}
	if cookieBySuffix(r, "session_token") != nil {
		t.Fatal("session cookie must not be set with a challenge")
	}
	if c := cookieBySuffix(r, "two_factor"); c == nil || c.Value != "signed" {
		t.Fatalf("challenge cookie missing: %v", r.Header["Set-Cookie"])
	}
	// Step 3: the interceptor saw the phone sign-in with its session and rememberMe
	if len(events) != 1 || events[0].Path != "/sign-in/phone-number" || events[0].Session == nil || events[0].Session.User.ID != uid || !events[0].DontRemember || events[0].Request == nil {
		t.Fatalf("events = %+v", events)
	}
	// Step 4: verify (not a sign-in path for two-factor) is not intercepted
	h2 := newHarness(t, signUpConfig())
	called := false
	h2.Auth.Hooks().OnAfterSignIn(func(context.Context, plugins.SignInEvent) (*plugins.SignInChallenge, error) {
		called = true
		return nil, nil
	})
	expectOK(t, h2.sendAndVerify(t, "+15550001008", nil))
	if called {
		t.Fatal("verify must not run sign-in interceptors")
	}
}

func TestSignInHookErrorsPropagate(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550001010"
	h.phoneUser(t, "banned@example.com", "password123", phone, true)
	h.Auth.Hooks().OnAfterSignIn(func(context.Context, plugins.SignInEvent) (*plugins.SignInChallenge, error) {
		return nil, errBlocked
	})
	r := signIn(h, t, phone, "password123")
	expectError(t, r, http.StatusForbidden, "BLOCKED")
}

func TestUpdateUserRejectsPhoneNumber(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	uid, cookies := h.signUpEmail(t, "upd@example.com", "password123")
	// better-auth's before hook answers PHONE_NUMBER_CANNOT_BE_UPDATED; goauth's update-user allowlist
	// rejects every unknown field first (FIELD_NOT_ALLOWED, 400)
	r := h.Post(t, "/api/auth/update-user", map[string]any{"phoneNumber": "+15550001099"}, withCookie(cookies))
	if r.Status != http.StatusBadRequest {
		t.Fatalf("status = %d (%s)", r.Status, r.Body)
	}
	u, _ := h.Auth.Repositories().FindUserByID(context.Background(), uid)
	if u.PhoneNumber != nil {
		t.Fatal("phone number must not be settable through update-user")
	}
}

func TestDisabledOps(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{}, func(c *config.AuthConfig) {
		c.DisabledOps = append(c.DisabledOps, "signInPhoneNumber")
		c.DisabledPaths = append(c.DisabledPaths, "/phone-number/reset-password")
	})
	if r := signIn(h, t, "+1555", "x"); r.Status != http.StatusNotFound && r.Status != http.StatusMethodNotAllowed {
		t.Fatalf("disabled sign-in status = %d", r.Status)
	}
	if r := h.Post(t, "/api/auth/phone-number/reset-password", map[string]any{"phoneNumber": "+1", "otp": "1", "newPassword": "x"}); r.Status != http.StatusNotFound && r.Status != http.StatusMethodNotAllowed {
		t.Fatalf("disabled reset status = %d", r.Status)
	}
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+1555"}))
}
