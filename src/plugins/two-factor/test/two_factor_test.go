package test

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	"github.com/better-go-auth/goauth/src/plugins/two-factor/services"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// ─── Pure crypto ─────────────────────────────────────────────────────────────

func TestTOTP_RFC6238Vectors(t *testing.T) {
	// RFC 6238 appendix B, SHA1 key "12345678901234567890", 8 digits
	secret := "12345678901234567890"
	cases := map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	}
	for ts, want := range cases {
		if got := services.TOTP(secret, time.Unix(ts, 0), 30*time.Second, 8); got != want {
			t.Errorf("TOTP(%d) = %s, want %s", ts, got, want)
		}
	}
	// RFC 4226 appendix D HOTP values (6 digits)
	hotp := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, want := range hotp {
		if got := services.HOTP(secret, uint64(i), 6); got != want {
			t.Errorf("HOTP(%d) = %s, want %s", i, got, want)
		}
	}
}

func TestTOTP_VerifyWindow(t *testing.T) {
	secret := "abcdefghijklmnopqrstuvwxyz012345"
	now := time.Unix(1_700_000_000, 0)
	for _, off := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if !services.VerifyTOTP(secret, services.TOTP(secret, now.Add(off), 30*time.Second, 6), now, 30*time.Second, 6) {
			t.Errorf("code at offset %v should verify", off)
		}
	}
	for _, off := range []time.Duration{-90 * time.Second, 90 * time.Second} {
		if services.VerifyTOTP(secret, services.TOTP(secret, now.Add(off), 30*time.Second, 6), now, 30*time.Second, 6) {
			t.Errorf("code at offset %v should not verify", off)
		}
	}
}

func TestTOTPURI_Format(t *testing.T) {
	// same output as @better-auth/utils/otp createOTP("abc").url("My App", "a+b@x.com")
	got := services.TOTPURI("abc", "My App", "a+b@x.com", 6, 30*time.Second)
	want := "otpauth://totp/My%20App:a%2Bb%40x.com?secret=MFRGG&issuer=My+App&digits=6&period=30"
	if got != want {
		t.Fatalf("uri =\n %s\nwant\n %s", got, want)
	}
	if s, err := services.ParseTOTPURI(got); err != nil || s != "abc" {
		t.Fatalf("ParseTOTPURI = %q, %v", s, err)
	}
}

func TestTrustDeviceTokenAndHash(t *testing.T) {
	tok := services.TrustDeviceToken("secret", "user-1", "trust-device-x")
	if len(tok) != 43 || strings.ContainsAny(tok, "+/=") {
		t.Fatalf("token is not base64url without padding: %q", tok)
	}
	if services.HashOTP("123456") != "jZae727K08KaOmKSgOaGzww_XVqGr_PKEgIMkjrcbJI" {
		t.Fatalf("HashOTP mismatch: %s", services.HashOTP("123456"))
	}
}

// ─── Enable ──────────────────────────────────────────────────────────────────

func TestEnable_PasswordRules(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	e.signUp("enable@example.com")

	// missing password → body validation error
	expectError(t, e.post("/two-factor/enable", map[string]any{}), 400, "VALIDATION_ERROR")
	// wrong password
	expectError(t, e.post("/two-factor/enable", map[string]any{"password": "wrong-password"}), 400, "INVALID_PASSWORD")
	// no session
	old := e.newDevice()
	expectError(t, e.post("/two-factor/enable", map[string]any{"password": password}), 401, "UNAUTHORIZED")
	e.useJar(old)
}

func TestEnable_StoresEncryptedSecretAndCodes(t *testing.T) {
	e := newEnv(t, tfconfig.Config{Issuer: "Issuer Co"}, false)
	id := e.signUp("store@example.com")

	r := e.post("/two-factor/enable", map[string]any{"password": password})
	expectStatus(t, r, 200)
	var body struct {
		TotpURI     string   `json:"totpURI"`
		BackupCodes []string `json:"backupCodes"`
	}
	r.JSON(t, &body)

	// Step 1: URI shape (issuer option, account = email)
	if !strings.HasPrefix(body.TotpURI, "otpauth://totp/Issuer%20Co:store%40example.com?secret=") ||
		!strings.HasSuffix(body.TotpURI, "&issuer=Issuer+Co&digits=6&period=30") {
		t.Fatalf("unexpected totpURI %s", body.TotpURI)
	}
	secret, _ := services.ParseTOTPURI(body.TotpURI)
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`).MatchString(secret) {
		t.Fatalf("secret should be 32 random chars, got %q", secret)
	}
	// Step 2: backup codes "xxxxx-xxxxx"
	if len(body.BackupCodes) != 10 {
		t.Fatalf("want 10 backup codes, got %d", len(body.BackupCodes))
	}
	for _, c := range body.BackupCodes {
		if !regexp.MustCompile(`^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$`).MatchString(c) {
			t.Fatalf("bad backup code %q", c)
		}
	}
	// Step 3: stored row: encrypted secret, encrypted JSON codes, unverified, user not yet enabled
	row := e.row(id)
	if row == nil || row.Verified {
		t.Fatalf("row should exist unverified: %+v", row)
	}
	plain, err := authcrypto.SymmetricDecrypt(compattest.TestSecret, row.Secret)
	if err != nil || plain != secret {
		t.Fatalf("decrypted secret = %q (%v), want %q", plain, err, secret)
	}
	codesJSON, err := authcrypto.SymmetricDecrypt(compattest.TestSecret, row.BackupCodes)
	if err != nil {
		t.Fatalf("decrypt backup codes: %v", err)
	}
	var codes []string
	if err := json.Unmarshal([]byte(codesJSON), &codes); err != nil || strings.Join(codes, ",") != strings.Join(body.BackupCodes, ",") {
		t.Fatalf("stored codes %s != returned", codesJSON)
	}
	if e.user(id).TwoFactorEnabled {
		t.Fatal("2FA must not be enabled before the first TOTP verification")
	}

	// Step 4: custom issuer from the body wins
	r = e.post("/two-factor/enable", map[string]any{"password": password, "issuer": "Body Issuer"})
	expectStatus(t, r, 200)
	r.JSON(t, &body)
	if !strings.HasPrefix(body.TotpURI, "otpauth://totp/Body%20Issuer:") {
		t.Fatalf("issuer from body not used: %s", body.TotpURI)
	}
	// re-enabling replaced the row (still one row)
	var n int64
	e.s.DB.Table("twoFactor").Where("user_id = ?", id).Count(&n)
	if n != 1 {
		t.Fatalf("want 1 twoFactor row, got %d", n)
	}
}

func TestEnable_AllowPasswordless(t *testing.T) {
	strict := newEnv(t, tfconfig.Config{}, false)
	id := strict.signUp("strict@example.com")
	removePassword(t, strict, id)
	expectError(t, strict.post("/two-factor/enable", map[string]any{}), 400, "VALIDATION_ERROR")
	expectError(t, strict.post("/two-factor/enable", map[string]any{"password": "anything"}), 400, "INVALID_PASSWORD")

	e := newEnv(t, tfconfig.Config{AllowPasswordless: true}, false)
	// a user with a password still needs it
	e.signUp("haspw@example.com")
	expectError(t, e.post("/two-factor/enable", map[string]any{}), 400, "INVALID_PASSWORD")
	expectStatus(t, e.post("/two-factor/enable", map[string]any{"password": password}), 200)

	// a passwordless user does not
	e.newDevice()
	id = e.signUp("nopw@example.com")
	removePassword(t, e, id)
	r := e.post("/two-factor/enable", map[string]any{})
	expectStatus(t, r, 200)
	var body struct {
		TotpURI string `json:"totpURI"`
	}
	r.JSON(t, &body)
	secret, _ := services.ParseTOTPURI(body.TotpURI)
	expectStatus(t, e.post("/two-factor/get-totp-uri", map[string]any{}), 200)
	expectStatus(t, e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret)}), 200)
	expectStatus(t, e.post("/two-factor/generate-backup-codes", map[string]any{}), 200)
	expectStatus(t, e.post("/two-factor/disable", map[string]any{}), 200)
}

func removePassword(t *testing.T, e *env, userID string) {
	t.Helper()
	if err := e.s.DB.Model(&models.Account{}).Where("user_id = ?", userID).Update("password", nil).Error; err != nil {
		t.Fatalf("remove password: %v", err)
	}
}

func TestEnable_SkipVerificationOnEnable(t *testing.T) {
	e := newEnv(t, tfconfig.Config{SkipVerificationOnEnable: true}, false)
	id := e.signUp("skip@example.com")
	before := e.cookie("session_token")
	e.enable()
	if !e.user(id).TwoFactorEnabled || !e.row(id).Verified {
		t.Fatal("skipVerificationOnEnable should enable 2FA immediately")
	}
	if after := e.cookie("session_token"); after == "" || after == before {
		t.Fatal("session cookie should be rotated")
	}
	if exists, enabled := e.session(); !exists || !enabled {
		t.Fatalf("session should reflect twoFactorEnabled (exists=%v enabled=%v)", exists, enabled)
	}
	e.signOut()
	if m := e.challenge("skip@example.com"); strings.Join(m, ",") != "totp" {
		t.Fatalf("methods = %v", m)
	}
}

// ─── TOTP ────────────────────────────────────────────────────────────────────

func TestVerifyTOTP_EnablesAndRotatesSession(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	id := e.signUp("verify@example.com")
	secret, _ := e.enable()
	oldToken := e.cookie("session_token")

	// wrong code
	expectError(t, e.post("/two-factor/verify-totp", map[string]any{"code": "000000"}), 401, "INVALID_CODE")

	// right code → enabled, new session, old session revoked
	r := e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret)})
	expectStatus(t, r, 200)
	var body struct {
		Token string `json:"token"`
		User  struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(t, &body)
	if body.Token == "" || body.User.ID != id {
		t.Fatalf("unexpected body %s", r.Body)
	}
	if !e.user(id).TwoFactorEnabled || !e.row(id).Verified {
		t.Fatal("2FA should be enabled and verified")
	}
	newToken := e.cookie("session_token")
	if newToken == "" || newToken == oldToken {
		t.Fatal("session cookie should be rotated")
	}
	if exists, enabled := e.session(); !exists || !enabled {
		t.Fatal("new session should carry twoFactorEnabled")
	}
	e.setCookie("session_token", oldToken)
	if exists, _ := e.session(); exists {
		t.Fatal("old session must be revoked")
	}
}

func TestGetTOTPURI(t *testing.T) {
	e := newEnv(t, tfconfig.Config{Issuer: "Ignored By get-totp-uri"}, false)
	e.signUp("uri@example.com")
	expectError(t, e.post("/two-factor/get-totp-uri", map[string]any{"password": password}), 400, "TOTP_NOT_ENABLED")
	secret, _ := e.enable()
	expectError(t, e.post("/two-factor/get-totp-uri", map[string]any{}), 400, "VALIDATION_ERROR")
	expectError(t, e.post("/two-factor/get-totp-uri", map[string]any{"password": "bad-password"}), 400, "INVALID_PASSWORD")
	r := e.post("/two-factor/get-totp-uri", map[string]any{"password": password})
	expectStatus(t, r, 200)
	var body struct {
		TotpURI string `json:"totpURI"`
	}
	r.JSON(t, &body)
	got, _ := services.ParseTOTPURI(body.TotpURI)
	if got != secret {
		t.Fatal("get-totp-uri should return the stored secret")
	}
	// better-auth's totp sub-plugin uses the app name
	if !strings.HasPrefix(body.TotpURI, "otpauth://totp/GoAuth%20Test:uri%40example.com?") {
		t.Fatalf("unexpected uri %s", body.TotpURI)
	}
}

func TestSignIn_ChallengeThenVerifyTOTP(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	id, secret, _ := e.enableFully("signin@example.com")

	// Step 1: credential sign-in answers the challenge, sets two_factor and no session
	r := e.signIn("signin@example.com")
	expectStatus(t, r, 200)
	var ch map[string]any
	r.JSON(t, &ch)
	if ch["twoFactorRedirect"] != true || len(ch) != 2 {
		t.Fatalf("unexpected challenge %s", r.Body)
	}
	if m, _ := ch["twoFactorMethods"].([]any); len(m) != 1 || m[0] != "totp" {
		t.Fatalf("methods = %v", ch["twoFactorMethods"])
	}
	if c := r.Cookie("better-auth.two_factor"); c == nil || c.MaxAge != 600 || !c.HttpOnly {
		t.Fatalf("two_factor cookie missing or wrong: %+v", c)
	}
	if c := r.Cookie("better-auth.session_token"); c == nil || c.MaxAge >= 0 {
		t.Fatalf("session_token must be expired: %+v", c)
	}
	if exists, _ := e.session(); exists {
		t.Fatal("no session before the second factor")
	}
	if rows := e.verificationByPrefix("2fa-"); len(rows) != 1 || rows[0].Value != id {
		t.Fatalf("expected one 2fa verification row, got %+v", rows)
	}
	var sessions int64
	e.s.DB.Model(&models.Session{}).Where("user_id = ?", id).Count(&sessions)
	if sessions != 0 {
		t.Fatalf("the sign-in session must be deleted, found %d", sessions)
	}
	twoFactorCookie := e.cookie("two_factor")

	// Step 2: without the cookie → INVALID_TWO_FACTOR_COOKIE
	jar := e.newDevice()
	expectError(t, e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret)}), 401, "INVALID_TWO_FACTOR_COOKIE")
	e.setCookie("two_factor", "forged.value")
	expectError(t, e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret)}), 401, "INVALID_TWO_FACTOR_COOKIE")
	e.useJar(jar)

	// Step 3: wrong code
	expectError(t, e.post("/two-factor/verify-totp", map[string]any{"code": "123"}), 401, "INVALID_CODE")

	// Step 4: right code → session
	r = e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret)})
	expectStatus(t, r, 200)
	var body struct {
		Token string `json:"token"`
		User  struct {
			ID               string `json:"id"`
			TwoFactorEnabled bool   `json:"twoFactorEnabled"`
		} `json:"user"`
	}
	r.JSON(t, &body)
	if body.Token == "" || body.User.ID != id || !body.User.TwoFactorEnabled {
		t.Fatalf("unexpected body %s", r.Body)
	}
	if c := r.Cookie("better-auth.two_factor"); c == nil || c.MaxAge >= 0 {
		t.Fatal("two_factor cookie should be expired")
	}
	if exists, enabled := e.session(); !exists || !enabled {
		t.Fatal("expected a session after verification")
	}
	if rows := e.verificationByPrefix("2fa-"); len(rows) != 0 {
		t.Fatal("2fa verification row should be consumed")
	}

	// Step 5: replaying the old two_factor cookie fails
	e.newDevice()
	e.setCookie("two_factor", twoFactorCookie)
	expectError(t, e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret)}), 401, "INVALID_TWO_FACTOR_COOKIE")
}

func TestSignIn_UserWithout2FAUnaffected(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, true)
	e.signUp("plain@example.com")
	e.signOut()
	r := e.signIn("plain@example.com")
	expectStatus(t, r, 200)
	if strings.Contains(string(r.Body), "twoFactorRedirect") || r.Cookie("better-auth.session_token") == nil {
		t.Fatalf("plain sign-in changed: %s", r.Body)
	}
}

func TestSignIn_PendingCookieExpires(t *testing.T) {
	e := newEnv(t, tfconfig.Config{TwoFactorCookieMaxAge: time.Minute}, false)
	_, secret, _ := e.enableFully("pending@example.com")
	e.challenge("pending@example.com")
	e.plugin.Service().SetClock(func() time.Time { return time.Now().Add(2 * time.Minute) })
	defer e.plugin.Service().SetClock(time.Now)
	expectError(t, e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret)}), 401, "INVALID_TWO_FACTOR_COOKIE")
}

func TestTOTPDisabled(t *testing.T) {
	e := newEnv(t, tfconfig.Config{SkipVerificationOnEnable: true, TOTPOptions: tfconfig.TOTPOptions{Disable: true}}, true)
	e.signUp("nototp@example.com")
	e.enable()
	expectError(t, e.post("/two-factor/get-totp-uri", map[string]any{"password": password}), 400, "TOTP_NOT_CONFIGURED")
	expectError(t, e.post("/two-factor/verify-totp", map[string]any{"code": "123456"}), 400, "TOTP_NOT_CONFIGURED")
	e.signOut()
	if m := e.challenge("nototp@example.com"); strings.Join(m, ",") != "otp" {
		t.Fatalf("methods = %v, want [otp]", m)
	}
	if _, err := e.plugin.GenerateTOTP("x"); err == nil {
		t.Fatal("GenerateTOTP should fail when TOTP is disabled")
	}
}

func TestGenerateTOTPServerMethod(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	secret := "my-secret-1234567890"
	code, err := e.plugin.GenerateTOTP(secret)
	if err != nil || code != services.TOTP(secret, time.Now(), 30*time.Second, 6) {
		t.Fatalf("GenerateTOTP = %q, %v", code, err)
	}
}

// ─── OTP ─────────────────────────────────────────────────────────────────────

func TestOTP_SignInFlow(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, true)
	id, _, _ := e.enableFully("otp@example.com")
	if m := e.challenge("otp@example.com"); strings.Join(m, ",") != "totp,otp" {
		t.Fatalf("methods = %v", m)
	}
	// Step 1: send
	r := e.post("/two-factor/send-otp", nil)
	expectStatus(t, r, 200)
	if strings.TrimSpace(string(r.Body)) != `{"status":true}` {
		t.Fatalf("send-otp body %s", r.Body)
	}
	otp := e.otps.get("otp@example.com")
	if !regexp.MustCompile(`^\d{6}$`).MatchString(otp) {
		t.Fatalf("otp %q", otp)
	}
	rows := e.verificationByPrefix("2fa-otp-2fa-")
	if len(rows) != 1 || rows[0].Value != otp+":0" {
		t.Fatalf("stored otp rows %+v", rows)
	}
	// Step 2: wrong code counts an attempt
	expectError(t, e.post("/two-factor/verify-otp", map[string]any{"code": "000000x"}), 401, "INVALID_CODE")
	if rows := e.verificationByPrefix("2fa-otp-2fa-"); rows[0].Value != otp+":1" {
		t.Fatalf("attempt not counted: %s", rows[0].Value)
	}
	// Step 3: right code signs in
	r = e.post("/two-factor/verify-otp", map[string]any{"code": otp})
	expectStatus(t, r, 200)
	var body struct {
		Token string `json:"token"`
		User  struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(t, &body)
	if body.Token == "" || body.User.ID != id {
		t.Fatalf("unexpected body %s", r.Body)
	}
	if exists, _ := e.session(); !exists {
		t.Fatal("expected a session")
	}
}

func TestOTP_EnablesTwoFactorWhenSignedIn(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, true)
	id := e.signUp("otpenable@example.com")
	expectStatus(t, e.post("/two-factor/send-otp", nil), 200)
	otp := e.otps.get("otpenable@example.com")
	r := e.post("/two-factor/verify-otp", map[string]any{"code": otp})
	expectStatus(t, r, 200)
	var body struct {
		Token string `json:"token"`
		User  struct {
			TwoFactorEnabled bool `json:"twoFactorEnabled"`
		} `json:"user"`
	}
	r.JSON(t, &body)
	if !body.User.TwoFactorEnabled || !e.user(id).TwoFactorEnabled || body.Token != e.cookieToken() {
		t.Fatalf("verify-otp should enable 2FA and return the new session: %s", r.Body)
	}
}

// cookieToken returns the token part of the signed session cookie.
func (e *env) cookieToken() string {
	v := e.cookie("session_token")
	if i := strings.IndexByte(v, '.'); i > 0 {
		return v[:i]
	}
	return v
}

func TestOTP_TooManyAttempts(t *testing.T) {
	e := newEnv(t, tfconfig.Config{OTPOptions: tfconfig.OTPOptions{AllowedAttempts: 2}}, true)
	e.enableFully("attempts@example.com")
	e.challenge("attempts@example.com")
	expectStatus(t, e.post("/two-factor/send-otp", nil), 200)
	otp := e.otps.get("attempts@example.com")
	expectError(t, e.post("/two-factor/verify-otp", map[string]any{"code": "bad1"}), 401, "INVALID_CODE")
	expectError(t, e.post("/two-factor/verify-otp", map[string]any{"code": "bad2"}), 401, "INVALID_CODE")
	expectError(t, e.post("/two-factor/verify-otp", map[string]any{"code": otp}), 400, "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE")
	// the code was burned
	expectError(t, e.post("/two-factor/verify-otp", map[string]any{"code": otp}), 400, "OTP_HAS_EXPIRED")
	// a new code works
	expectStatus(t, e.post("/two-factor/send-otp", nil), 200)
	expectStatus(t, e.post("/two-factor/verify-otp", map[string]any{"code": e.otps.get("attempts@example.com")}), 200)
}

func TestOTP_Expiry(t *testing.T) {
	e := newEnv(t, tfconfig.Config{OTPOptions: tfconfig.OTPOptions{Period: time.Minute}}, true)
	e.enableFully("expiry@example.com")
	e.challenge("expiry@example.com")
	// no code sent yet
	expectError(t, e.post("/two-factor/verify-otp", map[string]any{"code": "123456"}), 400, "OTP_HAS_EXPIRED")
	expectStatus(t, e.post("/two-factor/send-otp", nil), 200)
	otp := e.otps.get("expiry@example.com")
	rows := e.verificationByPrefix("2fa-otp-")
	if d := time.Until(rows[0].ExpiresAt); d > time.Minute || d < 50*time.Second {
		t.Fatalf("otp expiry %v, want ~1m", d)
	}
	e.plugin.Service().SetClock(func() time.Time { return time.Now().Add(90 * time.Second) })
	defer e.plugin.Service().SetClock(time.Now)
	expectError(t, e.post("/two-factor/verify-otp", map[string]any{"code": otp}), 400, "OTP_HAS_EXPIRED")
	if rows := e.verificationByPrefix("2fa-otp-"); len(rows) != 0 {
		t.Fatal("expired otp should be deleted")
	}
}

func TestOTP_StoreModes(t *testing.T) {
	cases := map[string]struct {
		store tfconfig.StoreOTPConfig
		check func(t *testing.T, stored, otp string)
	}{
		"hashed": {tfconfig.StoreOTPConfig{Mode: tfconfig.StoreHashed}, func(t *testing.T, stored, otp string) {
			if stored != services.HashOTP(otp) {
				t.Fatalf("stored %q is not the hash", stored)
			}
		}},
		"encrypted": {tfconfig.StoreOTPConfig{Mode: tfconfig.StoreEncrypted}, func(t *testing.T, stored, otp string) {
			if plain, err := authcrypto.SymmetricDecrypt(compattest.TestSecret, stored); err != nil || plain != otp {
				t.Fatalf("stored %q does not decrypt to otp (%v)", stored, err)
			}
		}},
		"custom-hash": {tfconfig.StoreOTPConfig{Hash: func(s string) (string, error) { return "h-" + s, nil }}, func(t *testing.T, stored, otp string) {
			if stored != "h-"+otp {
				t.Fatalf("stored %q", stored)
			}
		}},
		"custom-encrypt": {tfconfig.StoreOTPConfig{
			Encrypt: func(s string) (string, error) { return "enc(" + s + ")", nil },
			Decrypt: func(s string) (string, error) { return strings.TrimSuffix(strings.TrimPrefix(s, "enc("), ")"), nil },
		}, func(t *testing.T, stored, otp string) {
			if stored != "enc("+otp+")" {
				t.Fatalf("stored %q", stored)
			}
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, tfconfig.Config{OTPOptions: tfconfig.OTPOptions{StoreOTP: tc.store, Digits: 8}}, true)
			e.enableFully("store@example.com")
			e.challenge("store@example.com")
			expectStatus(t, e.post("/two-factor/send-otp", nil), 200)
			otp := e.otps.get("store@example.com")
			if len(otp) != 8 {
				t.Fatalf("otp %q should have 8 digits", otp)
			}
			rows := e.verificationByPrefix("2fa-otp-")
			stored := strings.TrimSuffix(rows[0].Value, ":0")
			tc.check(t, stored, otp)
			expectError(t, e.post("/two-factor/verify-otp", map[string]any{"code": "00000000"}), 401, "INVALID_CODE")
			expectStatus(t, e.post("/two-factor/verify-otp", map[string]any{"code": otp}), 200)
		})
	}
}

func TestOTP_NotConfigured(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	e.signUp("noconf@example.com")
	expectError(t, e.post("/two-factor/send-otp", nil), 400, "OTP_NOT_CONFIGURED")
}

func TestOTP_SendFailureIsNotReported(t *testing.T) {
	e := newEnv(t, tfconfig.Config{OTPOptions: tfconfig.OTPOptions{
		SendOTP: func(context.Context, tfconfig.SendOTPData, *http.Request) error { return context.Canceled },
	}}, false)
	e.signUp("fail@example.com")
	expectStatus(t, e.post("/two-factor/send-otp", nil), 200)
}

// ─── Backup codes ────────────────────────────────────────────────────────────

func TestBackupCodes_SingleUseAndRegeneration(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	id, _, codes := e.enableFully("backup@example.com")

	// Step 1: sign in with a backup code
	e.challenge("backup@example.com")
	expectError(t, e.post("/two-factor/verify-backup-code", map[string]any{"code": "nope-nope1"}), 401, "INVALID_BACKUP_CODE")
	r := e.post("/two-factor/verify-backup-code", map[string]any{"code": codes[0]})
	expectStatus(t, r, 200)
	if exists, _ := e.session(); !exists {
		t.Fatal("expected a session after a backup code")
	}
	remaining, err := e.plugin.ViewBackupCodes(context.Background(), id)
	if err != nil || len(remaining) != 9 {
		t.Fatalf("ViewBackupCodes = %d codes, %v", len(remaining), err)
	}

	// Step 2: the same code cannot be used again
	e.signOut()
	e.challenge("backup@example.com")
	expectError(t, e.post("/two-factor/verify-backup-code", map[string]any{"code": codes[0]}), 401, "INVALID_BACKUP_CODE")
	expectStatus(t, e.post("/two-factor/verify-backup-code", map[string]any{"code": codes[1]}), 200)

	// Step 3: regenerate (password required)
	expectError(t, e.post("/two-factor/generate-backup-codes", map[string]any{}), 400, "VALIDATION_ERROR")
	expectError(t, e.post("/two-factor/generate-backup-codes", map[string]any{"password": "bad-password"}), 400, "INVALID_PASSWORD")
	r = e.post("/two-factor/generate-backup-codes", map[string]any{"password": password})
	expectStatus(t, r, 200)
	var body struct {
		Status      bool     `json:"status"`
		BackupCodes []string `json:"backupCodes"`
	}
	r.JSON(t, &body)
	if !body.Status || len(body.BackupCodes) != 10 {
		t.Fatalf("unexpected body %s", r.Body)
	}
	view, _ := e.plugin.ViewBackupCodes(context.Background(), id)
	if strings.Join(view, ",") != strings.Join(body.BackupCodes, ",") {
		t.Fatal("ViewBackupCodes should return the regenerated codes")
	}
	// old codes no longer work
	e.signOut()
	e.challenge("backup@example.com")
	expectError(t, e.post("/two-factor/verify-backup-code", map[string]any{"code": codes[2]}), 401, "INVALID_BACKUP_CODE")
	expectStatus(t, e.post("/two-factor/verify-backup-code", map[string]any{"code": body.BackupCodes[0]}), 200)

	// Step 4: view for a user without 2FA
	if _, err := e.plugin.ViewBackupCodes(context.Background(), "missing"); err == nil {
		t.Fatal("ViewBackupCodes should fail without a twoFactor row")
	}
}

func TestBackupCodes_DisableSession(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	_, _, codes := e.enableFully("nosession@example.com")
	e.challenge("nosession@example.com")
	r := e.post("/two-factor/verify-backup-code", map[string]any{"code": codes[0], "disableSession": true})
	expectStatus(t, r, 200)
	var body map[string]any
	r.JSON(t, &body)
	if _, hasToken := body["token"]; hasToken || body["user"] == nil {
		t.Fatalf("disableSession should answer {user} only: %s", r.Body)
	}
	if r.Cookie("better-auth.session_token") != nil {
		t.Fatal("no session cookie with disableSession")
	}
	if exists, _ := e.session(); exists {
		t.Fatal("no session with disableSession")
	}
}

func TestBackupCodes_GenerateRequiresTwoFactor(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	e.signUp("gen@example.com")
	expectError(t, e.post("/two-factor/generate-backup-codes", map[string]any{"password": password}), 400, "TWO_FACTOR_NOT_ENABLED")
}

func TestBackupCodes_PlainAndCustomStorage(t *testing.T) {
	e := newEnv(t, tfconfig.Config{BackupCodeOptions: tfconfig.BackupCodeOptions{
		StoreBackupCodes: tfconfig.StoreBackupCodesConfig{Mode: tfconfig.StorePlain},
		Amount:           3, Length: 8,
	}}, false)
	id := e.signUp("plain-codes@example.com")
	_, codes := e.enable()
	if len(codes) != 3 || len(codes[0]) != 9 {
		t.Fatalf("codes %v", codes)
	}
	raw, _ := json.Marshal(codes)
	if e.row(id).BackupCodes != string(raw) {
		t.Fatalf("plain codes stored as %q", e.row(id).BackupCodes)
	}

	custom := newEnv(t, tfconfig.Config{BackupCodeOptions: tfconfig.BackupCodeOptions{
		CustomBackupCodesGenerate: func() []string { return []string{"one", "two"} },
		StoreBackupCodes: tfconfig.StoreBackupCodesConfig{
			Encrypt: func(s string) (string, error) { return "x" + s, nil },
			Decrypt: func(s string) (string, error) { return strings.TrimPrefix(s, "x"), nil },
		},
	}}, false)
	id = custom.signUp("custom-codes@example.com")
	_, codes = custom.enable()
	if strings.Join(codes, ",") != "one,two" || custom.row(id).BackupCodes != `x["one","two"]` {
		t.Fatalf("custom codes %v stored %q", codes, custom.row(id).BackupCodes)
	}
}

// ─── Trust device ────────────────────────────────────────────────────────────

func TestTrustDevice_SkipsAndRotates(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	id, secret, _ := e.enableFully("trust@example.com")

	// Step 1: verify with trustDevice
	e.challenge("trust@example.com")
	r := e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret), "trustDevice": true})
	expectStatus(t, r, 200)
	c := r.Cookie("better-auth.trust_device")
	if c == nil || c.MaxAge != 30*24*3600 {
		t.Fatalf("trust_device cookie %+v", c)
	}
	first := e.cookie("trust_device")
	if rows := e.verificationByPrefix("trust-device-"); len(rows) != 1 || rows[0].Value != id {
		t.Fatalf("trust rows %+v", rows)
	}

	// Step 2: next sign-in on this device skips 2FA and rotates the cookie
	e.signOut()
	r = e.signIn("trust@example.com")
	expectStatus(t, r, 200)
	var body struct {
		Token             string `json:"token"`
		TwoFactorRedirect bool   `json:"twoFactorRedirect"`
	}
	r.JSON(t, &body)
	if body.Token == "" || body.TwoFactorRedirect {
		t.Fatalf("trusted device should sign in directly: %s", r.Body)
	}
	second := e.cookie("trust_device")
	if second == "" || second == first {
		t.Fatal("trust_device cookie should be rotated")
	}
	if rows := e.verificationByPrefix("trust-device-"); len(rows) != 1 {
		t.Fatalf("old trust record should be replaced, got %d", len(rows))
	}
	if exists, _ := e.session(); !exists {
		t.Fatal("expected a session")
	}

	// Step 3: the old (rotated) cookie no longer works on another device and is expired
	e.newDevice()
	e.setCookie("trust_device", first)
	r = e.signIn("trust@example.com")
	expectStatus(t, r, 200)
	if !strings.Contains(string(r.Body), `"twoFactorRedirect":true`) {
		t.Fatalf("rotated cookie must not skip 2FA: %s", r.Body)
	}
	if c := r.Cookie("better-auth.trust_device"); c == nil || c.MaxAge >= 0 {
		t.Fatal("invalid trust_device cookie should be expired")
	}

	// Step 4: a trust cookie of another user does not apply
	other := newEnv(t, tfconfig.Config{}, false)
	other.enableFully("trust@example.com")
	other.setCookie("trust_device", second)
	other.challenge("trust@example.com")
}

func TestTrustDevice_Expired(t *testing.T) {
	e := newEnv(t, tfconfig.Config{TrustDeviceMaxAge: time.Hour}, false)
	_, secret, _ := e.enableFully("trustexp@example.com")
	e.challenge("trustexp@example.com")
	expectStatus(t, e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret), "trustDevice": true}), 200)
	e.signOut()
	e.plugin.Service().SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	defer e.plugin.Service().SetClock(time.Now)
	e.challenge("trustexp@example.com")
}

// ─── Disable ─────────────────────────────────────────────────────────────────

func TestDisable(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	id, secret, _ := e.enableFully("disable@example.com")
	e.challenge("disable@example.com")
	expectStatus(t, e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret), "trustDevice": true}), 200)
	oldToken := e.cookie("session_token")

	expectError(t, e.post("/two-factor/disable", map[string]any{}), 400, "VALIDATION_ERROR")
	expectError(t, e.post("/two-factor/disable", map[string]any{"password": "bad-password"}), 400, "INVALID_PASSWORD")
	r := e.post("/two-factor/disable", map[string]any{"password": password})
	expectStatus(t, r, 200)
	if strings.TrimSpace(string(r.Body)) != `{"status":true}` {
		t.Fatalf("body %s", r.Body)
	}
	if e.user(id).TwoFactorEnabled || e.row(id) != nil {
		t.Fatal("2FA should be off and the row deleted")
	}
	if c := r.Cookie("better-auth.trust_device"); c == nil || c.MaxAge >= 0 {
		t.Fatal("trust_device should be expired")
	}
	if rows := e.verificationByPrefix("trust-device-"); len(rows) != 0 {
		t.Fatal("trust record should be deleted")
	}
	if tok := e.cookie("session_token"); tok == "" || tok == oldToken {
		t.Fatal("session should be rotated")
	}
	if exists, enabled := e.session(); !exists || enabled {
		t.Fatal("session should show twoFactorEnabled=false")
	}
	e.signOut()
	r = e.signIn("disable@example.com")
	expectStatus(t, r, 200)
	if strings.Contains(string(r.Body), "twoFactorRedirect") {
		t.Fatal("sign-in should no longer be challenged")
	}
}

func TestDisable_RequiresFreshSession(t *testing.T) {
	e := newEnv(t, tfconfig.Config{SkipVerificationOnEnable: true}, false, func(c *config.AuthConfig) {
		c.Session.FreshAge = 300 * time.Millisecond
	})
	e.signUp("fresh@example.com")
	e.enable()
	time.Sleep(400 * time.Millisecond)
	expectError(t, e.post("/two-factor/disable", map[string]any{"password": password}), 403, "SESSION_NOT_FRESH")
}

// ─── rememberMe=false ────────────────────────────────────────────────────────

func TestRememberMeFalse(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	_, secret, _ := e.enableFully("remember@example.com")
	r := e.signIn("remember@example.com", map[string]any{"rememberMe": false})
	expectStatus(t, r, 200)
	if c := r.Cookie("better-auth.dont_remember"); c == nil || c.MaxAge != 0 || c.Value == "" {
		t.Fatalf("challenge should keep dont_remember: %+v", c)
	}
	r = e.post("/two-factor/verify-totp", map[string]any{"code": e.totp(secret)})
	expectStatus(t, r, 200)
	c := r.Cookie("better-auth.session_token")
	if c == nil || c.MaxAge != 0 || c.Value == "" {
		t.Fatalf("session cookie should be a browser-session cookie: %+v", c)
	}
	var s models.Session
	e.s.DB.Order("created_at desc").Take(&s)
	if d := time.Until(s.ExpiresAt); d > 25*time.Hour {
		t.Fatalf("dontRemember session should last ~1 day, got %v", d)
	}
}

// ─── Cleanup & rate limit ────────────────────────────────────────────────────

func TestUserDeletionRemovesTwoFactor(t *testing.T) {
	e := newEnv(t, tfconfig.Config{SkipVerificationOnEnable: true}, false, func(c *config.AuthConfig) {
		c.User.DeleteUser.Enabled = true
	})
	id := e.signUp("delete@example.com")
	e.enable()
	if e.row(id) == nil {
		t.Fatal("row should exist")
	}
	expectStatus(t, e.post("/delete-user", map[string]any{"password": password}), 200)
	if e.row(id) != nil {
		t.Fatal("twoFactor row should be deleted with the user")
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false, func(c *config.AuthConfig) {
		c.RateLimit.Enabled = new(true)
	})
	for i := 0; i < 3; i++ {
		expectError(t, e.post("/two-factor/verify-totp", map[string]any{"code": "123456"}), 401, "INVALID_TWO_FACTOR_COOKIE")
	}
	r := e.post("/two-factor/verify-totp", map[string]any{"code": "123456"})
	expectStatus(t, r, 429)
	if r.Header.Get("X-Retry-After") == "" {
		t.Fatal("missing X-Retry-After")
	}
	// another two-factor path has its own counter
	expectError(t, e.post("/two-factor/verify-otp", map[string]any{"code": "123456"}), 401, "INVALID_TWO_FACTOR_COOKIE")
}

func TestMigrationTableName(t *testing.T) {
	e := newEnv(t, tfconfig.Config{}, false)
	if !e.s.DB.Migrator().HasTable("twoFactor") {
		t.Fatal(`table "twoFactor" missing`)
	}
	for _, col := range []string{"id", "secret", "backup_codes", "user_id", "verified"} {
		if !e.s.DB.Migrator().HasColumn("twoFactor", col) {
			t.Errorf("column %s missing", col)
		}
	}
}
