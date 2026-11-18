package coreopts

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	tfmodels "github.com/better-go-auth/goauth/src/plugins/two-factor/models"
	"github.com/better-go-auth/goauth/src/plugins/two-factor/services"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"gorm.io/gorm"
)

const (
	secretV1 = "rotation-e2e-secret-v1-0123456789abcdef"
	secretV2 = "rotation-e2e-secret-v2-0123456789abcdef"
)

// rotatingServer starts goauth with the two-factor plugin and the given secrets on db (nil = a new database).
func rotatingServer(t *testing.T, db *gorm.DB, secrets ...config.SecretVersion) *compattest.Server {
	t.Helper()
	opts := []compattest.Option{
		compattest.WithPlugin(twofactor.New(tfconfig.Config{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.Secret = ""
			c.Secrets = secrets
		}),
	}
	if db != nil {
		opts = append(opts, compattest.WithDB(db))
	}
	return compattest.NewServer(t, opts...)
}

func TestSecretRotationEndToEnd(t *testing.T) {
	// Step 1: server A signs and encrypts with v1; the user enables two-factor (TOTP secret encrypted at rest)
	a := rotatingServer(t, nil, config.SecretVersion{Version: 1, Value: secretV1})
	cookieV1 := cookieHeader(signUp(t, a, "rotate@example.com", nil))
	r := call(t, a, http.MethodPost, "/api/auth/two-factor/enable", map[string]any{"password": password}, map[string]string{"Cookie": cookieV1, "Origin": a.Origin})
	if r.Status != http.StatusOK {
		t.Fatalf("enable: %d %s", r.Status, r.Body)
	}
	var enabled struct {
		TotpURI string `json:"totpURI"`
	}
	r.JSON(t, &enabled)
	secret, _ := services.ParseTOTPURI(enabled.TotpURI)
	r = call(t, a, http.MethodPost, "/api/auth/two-factor/verify-totp", map[string]any{"code": services.TOTP(secret, time.Now(), 30*time.Second, 6)}, map[string]string{"Cookie": cookieV1, "Origin": a.Origin})
	if r.Status != http.StatusOK {
		t.Fatalf("verify-totp: %d %s", r.Status, r.Body)
	}
	// enabling two-factor replaces the session; the new cookie is still signed with v1
	cookieV1 = cookieHeader(r)
	// a second user without two-factor, signed in on A as well
	plainV1 := cookieHeader(signUp(t, a, "plain@example.com", nil))
	var row tfmodels.TwoFactor
	if err := a.DB.First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row.Secret, "$ba$1$") || !strings.HasPrefix(row.BackupCodes, "$ba$1$") {
		t.Fatalf("v1 envelopes expected: secret=%q codes=%q", row.Secret, row.BackupCodes)
	}

	// Step 2: server B rotates to v2 (v1 kept): the v1 cookie still signs in and the v1 data still decrypts
	b := rotatingServer(t, a.DB, config.SecretVersion{Version: 2, Value: secretV2}, config.SecretVersion{Version: 1, Value: secretV1})
	if got := sessionEmail(t, b, cookieV1); got != "rotate@example.com" {
		t.Fatalf("v1 cookie after rotation: %q", got)
	}
	if got := sessionEmail(t, b, plainV1); got != "plain@example.com" {
		t.Fatalf("v1 cookie of the second user after rotation: %q", got)
	}
	r = call(t, b, http.MethodPost, "/api/auth/two-factor/get-totp-uri", map[string]any{"password": password}, map[string]string{"Cookie": cookieV1, "Origin": b.Origin})
	if r.Status != http.StatusOK {
		t.Fatalf("get-totp-uri after rotation: %d %s", r.Status, r.Body)
	}
	var uri struct {
		TotpURI string `json:"totpURI"`
	}
	r.JSON(t, &uri)
	want, _ := services.ParseTOTPURI(enabled.TotpURI)
	got, _ := services.ParseTOTPURI(uri.TotpURI)
	if got == "" || got != want {
		t.Fatalf("v1-encrypted TOTP secret not decrypted: %q vs %q", got, want)
	}

	// Step 3: new cookies from B are signed with v2 (verifiable with v2 alone)
	signIn := call(t, b, http.MethodPost, "/api/auth/sign-in/email", map[string]any{"email": "plain@example.com", "password": password}, map[string]string{"Origin": b.Origin})
	tokenCookie := setCookie(signIn, "better-auth.session_token")
	if tokenCookie == nil {
		t.Fatalf("sign-in on B set no session cookie: %s", signIn.Body)
	}
	raw, _ := url.QueryUnescape(tokenCookie.Value)
	if _, ok := cookies.VerifyCookieValue(raw, secretV2); !ok {
		t.Fatal("new cookie must be signed with the current secret v2")
	}
	if _, ok := cookies.VerifyCookieValue(raw, secretV1); ok {
		t.Fatal("new cookie must not be signed with v1")
	}

	// Step 4: newly encrypted data uses the v2 envelope
	r = call(t, b, http.MethodPost, "/api/auth/two-factor/generate-backup-codes", map[string]any{"password": password}, map[string]string{"Cookie": cookieV1, "Origin": b.Origin})
	if r.Status != http.StatusOK {
		t.Fatalf("generate-backup-codes: %d %s", r.Status, r.Body)
	}
	if err := b.DB.First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row.BackupCodes, "$ba$2$") {
		t.Fatalf("v2 envelope expected after rotation, got %q", row.BackupCodes[:8])
	}

	// Step 5: server C retires v1: old cookies and v1 ciphertexts are rejected, v2 ones still work
	c := rotatingServer(t, a.DB, config.SecretVersion{Version: 2, Value: secretV2})
	if got := sessionEmail(t, c, cookieV1); got != "" {
		t.Fatalf("retired v1 cookie must not sign in, got %q", got)
	}
	if got := sessionEmail(t, c, cookieHeader(signIn)); got != "plain@example.com" {
		t.Fatalf("v2 cookie on C: %q", got)
	}
	if got := sessionEmail(t, c, plainV1); got != "" {
		t.Fatalf("retired v1 cookie of the second user must not sign in, got %q", got)
	}
}

// tsRotation are cookies written by a TypeScript better-auth 1.6 with secrets [v2, v1]
// (src/tests/compat/client/gen-secret-vectors.mjs).
type tsRotation struct {
	LegacySecret     string `json:"legacySecret"`
	SecretV1         string `json:"secretV1"`
	SecretV2         string `json:"secretV2"`
	CompactSessionV2 string `json:"compactSessionV2"`
	JWESessionV1     string `json:"jweSessionV1"`
	SignedCookieV1   string `json:"signedCookieV1"`
}

func TestTypeScriptRotatedCookiesSignIn(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "providers", "authcrypto", "testdata", "better_auth_rotation_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v tsRotation
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for strategy, cache := range map[config.CookieCacheStrategy]string{
		config.CookieCacheStrategyCompact: v.CompactSessionV2,
		config.CookieCacheStrategyJwe:     v.JWESessionV1,
	} {
		// Step 1: goauth configured like the TS server (same secrets, cookie cache on)
		s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
			c.Secret = v.LegacySecret
			c.Secrets = []config.SecretVersion{{Version: 2, Value: v.SecretV2}, {Version: 1, Value: v.SecretV1}}
			yes := true
			c.Session.CookieCache = &config.CookieCache{Enabled: &yes, Strategy: strategy}
		}))
		// Step 2: the TS session_token (signed with v1) + session_data cache are accepted by /get-session
		cookie := "better-auth.session_token=" + cookies.EncodeCookieValue(v.SignedCookieV1) + "; better-auth.session_data=" + cache
		if got := sessionEmail(t, s, cookie); got != "a@example.com" {
			t.Fatalf("%s: TS cookie cache not accepted, got %q", strategy, got)
		}
		// Step 3: a cache signed for another session token is ignored (falls back to the database: no session)
		other := "better-auth.session_token=" + cookies.EncodeCookieValue(cookies.SignCookieValue("other", v.SecretV2)) + "; better-auth.session_data=" + cache
		if got := sessionEmail(t, s, other); got != "" {
			t.Fatalf("%s: cache of another token must be ignored, got %q", strategy, got)
		}
	}
}
