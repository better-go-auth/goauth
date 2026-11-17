package test

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
)

func TestSendOTPStoresCodeWithAttempts(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550000001"

	// Step 1: send-otp answers {"message":"code sent"}
	r := h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone})
	expectOK(t, r)
	if strings.TrimSpace(string(r.Body)) != `{"message":"code sent"}` {
		t.Fatalf("body = %s", r.Body)
	}
	// Step 2: the SMS carries a 6 digit code
	code := h.sms.code(t, phone)
	if !regexp.MustCompile(`^\d{6}$`).MatchString(code) {
		t.Fatalf("code %q is not 6 digits", code)
	}
	// Step 3: verification row: identifier = phone, value = "code:0", expires in ~300s
	v := h.verification(t, phone)
	if v == nil {
		t.Fatal("no verification row")
	}
	if v.Value != code+":0" {
		t.Fatalf("value = %q, want %q", v.Value, code+":0")
	}
	if d := time.Until(v.ExpiresAt); d < 290*time.Second || d > 301*time.Second {
		t.Fatalf("expires in %v, want ~300s", d)
	}
	// Step 4: a resend replaces the code
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}))
	if v2 := h.verification(t, phone); v2 == nil || v2.Value != h.sms.code(t, phone)+":0" {
		t.Fatalf("resend did not store the new code: %+v", v2)
	}
}

func TestSendOTPCustomLengthAndExpiry(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{OTPLength: 8, ExpiresIn: time.Minute})
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+1555"}))
	if c := h.sms.code(t, "+1555"); len(c) != 8 {
		t.Fatalf("code %q, want 8 digits", c)
	}
	if d := time.Until(h.verification(t, "+1555").ExpiresAt); d > 61*time.Second || d < 50*time.Second {
		t.Fatalf("expires in %v, want ~60s", d)
	}
}

func TestSendOTPNotImplemented(t *testing.T) {
	h := newHarnessNoSender(t, phoneconfig.PhoneNumberConfig{})
	r := h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+1555"})
	expectError(t, r, http.StatusNotImplemented, "SEND_OTP_NOT_IMPLEMENTED")
	if h.verification(t, "+1555") != nil {
		t.Fatal("no code may be stored without a sender")
	}
}

func TestSendOTPSenderErrorFails(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{SendOTP: func(phoneconfig.OTPData, *http.Request) error {
		return errors.New("sms gateway down")
	}})
	r := h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+1555"})
	if r.Status < 500 {
		t.Fatalf("status = %d, want 5xx (%s)", r.Status, r.Body)
	}
}

func TestPhoneNumberValidator(t *testing.T) {
	valid := func(p string) bool { return regexp.MustCompile(`^\+\d{8,15}$`).MatchString(p) }
	h := newHarness(t, phoneconfig.PhoneNumberConfig{PhoneNumberValidator: valid})
	// send-otp rejects malformed numbers
	expectError(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "12"}), http.StatusBadRequest, "INVALID_PHONE_NUMBER")
	// sign-in rejects them before any lookup
	expectError(t, h.Post(t, "/api/auth/sign-in/phone-number", map[string]any{"phoneNumber": "abc", "password": "x"}), http.StatusBadRequest, "INVALID_PHONE_NUMBER")
	// valid numbers pass
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+155500000099"}))
}

func TestVerifyWrongCodeCountsAttemptsAndLocksOut(t *testing.T) {
	h := newHarness(t, signUpConfig())
	phone := "+15550000002"
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}))
	code := h.sms.code(t, phone)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	// Step 1: three wrong codes → INVALID_OTP, the counter climbs to 3
	for i := 1; i <= 3; i++ {
		r := h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": wrong})
		expectError(t, r, http.StatusBadRequest, "INVALID_OTP")
		var e errBody
		r.JSON(t, &e)
		if e.Message != "Invalid OTP" {
			t.Fatalf("message = %q", e.Message)
		}
		if v := h.verification(t, phone); v == nil || v.Value != code+":"+string(rune('0'+i)) {
			t.Fatalf("after %d wrong codes value = %+v", i, v)
		}
	}
	// Step 2: the 4th attempt is locked out even with the right code, and the code is deleted
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": code}), http.StatusForbidden, "TOO_MANY_ATTEMPTS")
	if h.verification(t, phone) != nil {
		t.Fatal("locked out code must be deleted")
	}
	// Step 3: further attempts find nothing
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": code}), http.StatusBadRequest, "OTP_NOT_FOUND")
}

func TestVerifyAllowedAttemptsOption(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{AllowedAttempts: 1})
	phone := "+15550000012"
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}))
	code := h.sms.code(t, phone)
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": "x"}), http.StatusBadRequest, "INVALID_OTP")
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": code}), http.StatusForbidden, "TOO_MANY_ATTEMPTS")
}

func TestVerifyExpiredAndNotFound(t *testing.T) {
	h := newHarness(t, signUpConfig())
	phone := "+15550000003"
	// Step 1: unknown number → OTP_NOT_FOUND
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": "123456"}), http.StatusBadRequest, "OTP_NOT_FOUND")
	// Step 2: expire a stored code → OTP_EXPIRED (the row is kept, like better-auth)
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}))
	v := h.verification(t, phone)
	v.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := h.Auth.Repositories().UpsertVerificationValue(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": h.sms.code(t, phone)}), http.StatusBadRequest, "OTP_EXPIRED")
}

func TestVerifyIsSingleUse(t *testing.T) {
	h := newHarness(t, signUpConfig())
	phone := "+15550000004"
	expectOK(t, h.sendAndVerify(t, phone, nil))
	if h.verification(t, phone) != nil {
		t.Fatal("code must be consumed")
	}
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": h.sms.code(t, phone)}), http.StatusBadRequest, "OTP_NOT_FOUND")
}

func TestSignUpOnVerification(t *testing.T) {
	cfg := signUpConfig()
	var callbacks []phoneconfig.VerificationData
	cfg.CallbackOnVerification = func(d phoneconfig.VerificationData, _ *http.Request) error {
		callbacks = append(callbacks, d)
		return nil
	}
	h := newHarness(t, cfg)
	phone := "+15550000005"

	// Step 1: verify an unknown number → user created and signed in
	r := h.sendAndVerify(t, phone, nil)
	expectOK(t, r)
	var body struct {
		Status bool           `json:"status"`
		Token  *string        `json:"token"`
		User   map[string]any `json:"user"`
	}
	r.JSON(t, &body)
	if !body.Status || body.Token == nil || *body.Token == "" {
		t.Fatalf("unexpected body %s", r.Body)
	}
	// Step 2: better-auth user shape with the phone fields
	if body.User["phoneNumber"] != phone || body.User["phoneNumberVerified"] != true {
		t.Fatalf("phone fields missing: %v", body.User)
	}
	if body.User["email"] != "15550000005@phone.example.invalid" || body.User["name"] != "User "+phone || body.User["emailVerified"] != false {
		t.Fatalf("temp email/name wrong: %v", body.User)
	}
	for _, k := range []string{"id", "createdAt", "updatedAt", "image"} {
		if _, ok := body.User[k]; !ok {
			t.Fatalf("user.%s missing: %v", k, body.User)
		}
	}
	// Step 3: the session cookie works with get-session
	if cookieBySuffix(r, "session_token") == nil {
		t.Fatal("session cookie not set")
	}
	sess := h.getSession(t, cookieHeader(r))
	if u := sess["user"].(map[string]any); u["phoneNumber"] != phone || u["phoneNumberVerified"] != true {
		t.Fatalf("get-session user = %v", u)
	}
	// Step 4: callbackOnVerification saw the new user
	if len(callbacks) != 1 || callbacks[0].PhoneNumber != phone || callbacks[0].User == nil || callbacks[0].User.ID != body.User["id"] {
		t.Fatalf("callbacks = %+v", callbacks)
	}
	// Step 5: verifying again signs the same user in (no duplicate)
	r2 := h.sendAndVerify(t, phone, nil)
	expectOK(t, r2)
	var body2 struct {
		User map[string]any `json:"user"`
	}
	r2.JSON(t, &body2)
	if body2.User["id"] != body.User["id"] {
		t.Fatalf("second verify created a new user: %v vs %v", body2.User["id"], body.User["id"])
	}
}

func TestSignUpOnVerificationDefaultsAndExtraFields(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{SignUpOnVerification: &phoneconfig.SignUpOnVerification{}})
	phone := "+15550000006"
	// Step 1: input:false plugin fields cannot be set on sign-up
	expectError(t, h.sendAndVerify(t, phone, map[string]any{"phoneNumberVerified": true}), http.StatusBadRequest, "FIELD_NOT_ALLOWED")
	// Step 2: unknown extra fields are ignored; defaults fill email and name
	r := h.sendAndVerify(t, phone, map[string]any{"name": "ignored", "favoriteColor": "blue"})
	expectOK(t, r)
	var body struct {
		User map[string]any `json:"user"`
	}
	r.JSON(t, &body)
	if body.User["name"] != phone || body.User["email"] != phone+"@phone.invalid" {
		t.Fatalf("defaults wrong: %v", body.User)
	}
}

func TestVerifyUnknownNumberWithoutSignUpFails(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	// better-auth throws FAILED_TO_UPDATE_USER (500) when no user exists and signUpOnVerification is off
	expectError(t, h.sendAndVerify(t, "+15550000007", nil), http.StatusInternalServerError, "FAILED_TO_UPDATE_USER")
}

func TestVerifyMarksExistingUserVerified(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	uid, _ := h.signUpEmail(t, "existing@example.com", "password123")
	phone := "+15550000008"
	h.setPhone(t, uid, phone, false)
	r := h.sendAndVerify(t, phone, nil)
	expectOK(t, r)
	var body struct {
		User map[string]any `json:"user"`
	}
	r.JSON(t, &body)
	if body.User["id"] != uid || body.User["phoneNumberVerified"] != true || body.User["email"] != "existing@example.com" {
		t.Fatalf("user = %v", body.User)
	}
	u, _ := h.Auth.Repositories().FindUserByID(context.Background(), uid)
	if !u.PhoneNumberVerified {
		t.Fatal("phoneNumberVerified not stored")
	}
}

func TestVerifyDisableSession(t *testing.T) {
	h := newHarness(t, signUpConfig())
	r := h.sendAndVerify(t, "+15550000009", map[string]any{"disableSession": true})
	expectOK(t, r)
	var body map[string]any
	r.JSON(t, &body)
	if tok, ok := body["token"]; !ok || tok != nil {
		t.Fatalf("token must be null: %s", r.Body)
	}
	if body["status"] != true || body["user"] == nil {
		t.Fatalf("body = %s", r.Body)
	}
	if cookieBySuffix(r, "session_token") != nil {
		t.Fatal("no session cookie expected")
	}
	var n int64
	h.DB.Model(&models.Session{}).Count(&n)
	if n != 0 {
		t.Fatalf("sessions = %d, want 0", n)
	}
}

func TestVerifyCustomVerifyOTP(t *testing.T) {
	cfg := signUpConfig()
	cfg.VerifyOTP = func(d phoneconfig.OTPData, _ *http.Request) (bool, error) { return d.Code == "424242", nil }
	h := newHarness(t, cfg)
	phone := "+15550000010"
	// Step 1: the custom verifier decides, the stored code is irrelevant
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}))
	expectError(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": h.sms.code(t, phone)}), http.StatusBadRequest, "INVALID_OTP")
	// Step 2: accepted code signs up and drops the stored row
	expectOK(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": "424242"}))
	if h.verification(t, phone) != nil {
		t.Fatal("stored code must be deleted after custom verification")
	}
	// Step 3: works without any stored code
	expectOK(t, h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": "+15550000011", "code": "424242"}))
}

func TestVerifyCallbackErrorAborts(t *testing.T) {
	cfg := signUpConfig()
	cfg.CallbackOnVerification = func(phoneconfig.VerificationData, *http.Request) error {
		return errors.New("nope")
	}
	h := newHarness(t, cfg)
	r := h.sendAndVerify(t, "+15550000013", nil)
	if r.Status < 500 {
		t.Fatalf("status = %d (%s)", r.Status, r.Body)
	}
	if cookieBySuffix(r, "session_token") != nil {
		t.Fatal("no session on callback failure")
	}
}

func TestUpdatePhoneNumber(t *testing.T) {
	h := newHarness(t, signUpConfig())
	uid, cookies := h.signUpEmail(t, "update@example.com", "password123")
	phone := "+15550000020"

	// Step 1: without a session → 401 USER_NOT_FOUND (after the code was consumed, like better-auth)
	expectError(t, h.sendAndVerify(t, phone, map[string]any{"updatePhoneNumber": true}), http.StatusUnauthorized, "USER_NOT_FOUND")

	// Step 2: with a session the number is attached and verified
	sess := h.getSession(t, cookies)
	token := sess["session"].(map[string]any)["token"]
	r := h.sendAndVerify(t, phone, map[string]any{"updatePhoneNumber": true}, withCookie(cookies))
	expectOK(t, r)
	var body struct {
		Status bool           `json:"status"`
		Token  *string        `json:"token"`
		User   map[string]any `json:"user"`
	}
	r.JSON(t, &body)
	if body.Token == nil || *body.Token != token {
		t.Fatalf("token = %v, want current session token %v", body.Token, token)
	}
	if body.User["id"] != uid || body.User["phoneNumber"] != phone || body.User["phoneNumberVerified"] != true {
		t.Fatalf("user = %v", body.User)
	}
	// Step 3: get-session (with the refreshed cookie cache) shows the number
	merged := cookies
	if c := cookieHeader(r); c != "" {
		merged = c
	}
	if u := h.getSession(t, merged)["user"].(map[string]any); u["phoneNumber"] != phone {
		t.Fatalf("get-session user = %v", u)
	}
	if u := h.getSession(t, cookies)["user"].(map[string]any); u["phoneNumber"] != phone {
		t.Fatalf("get-session (old cookies) user = %v", u)
	}

	// Step 4: a number owned by another user → PHONE_NUMBER_EXIST
	_, cookies2 := h.signUpEmail(t, "update2@example.com", "password123")
	expectError(t, h.sendAndVerify(t, phone, map[string]any{"updatePhoneNumber": true}, withCookie(cookies2)), http.StatusBadRequest, "PHONE_NUMBER_EXIST")
	// the caller's own number counts as taken too (better-auth findMany)
	expectError(t, h.sendAndVerify(t, phone, map[string]any{"updatePhoneNumber": true}, withCookie(cookies)), http.StatusBadRequest, "PHONE_NUMBER_EXIST")
}

func TestClearingPhoneNumberResetsVerified(t *testing.T) {
	h := newHarness(t, signUpConfig())
	r := h.sendAndVerify(t, "+15550000021", nil)
	expectOK(t, r)
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(t, &body)
	u, err := h.plugin.Service().UpdatePhoneNumber(context.Background(), body.User.ID, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if u.PhoneNumber != nil || u.PhoneNumberVerified {
		t.Fatalf("phone = %v verified = %v", u.PhoneNumber, u.PhoneNumberVerified)
	}
}

// TestVerifyConcurrentGuessesRespectAttemptLimit fires parallel wrong guesses: the attempt counter is a
// compare-and-swap, so no more than AllowedAttempts of them may be judged (INVALID_OTP).
func TestVerifyConcurrentGuessesRespectAttemptLimit(t *testing.T) {
	h := newHarness(t, phoneconfig.PhoneNumberConfig{})
	phone := "+15550000031"
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}))
	code := h.sms.code(t, phone)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	// Step 1: 12 wrong guesses at once
	var mu sync.Mutex
	codes := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var e errBody
			r := h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": wrong})
			r.JSON(t, &e)
			mu.Lock()
			codes[e.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	// Step 2: at most AllowedAttempts (3) guesses were evaluated
	if codes["INVALID_OTP"] > 3 {
		t.Fatalf("%d wrong guesses were evaluated, limit is 3 (%v)", codes["INVALID_OTP"], codes)
	}
}

// TestVerifyConcurrentCorrectCodeUsedOnce sends the right code in parallel: only one request may use it.
func TestVerifyConcurrentCorrectCodeUsedOnce(t *testing.T) {
	h := newHarness(t, signUpConfig())
	phone := "+15550000032"
	expectOK(t, h.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": phone}))
	code := h.sms.code(t, phone)
	// Step 1: 8 verifications with the correct code at once
	var ok int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := h.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": phone, "code": code}); r.Status == http.StatusOK {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	// Step 2: exactly one succeeded
	if ok != 1 {
		t.Fatalf("%d requests used the same code, want 1", ok)
	}
}
