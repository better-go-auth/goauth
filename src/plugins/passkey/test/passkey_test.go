package test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/passkey"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
	pkmodels "github.com/better-go-auth/goauth/src/plugins/passkey/models"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/fxamacker/cbor/v2"
)

const (
	base       = "/api/auth"
	appOrigin  = "http://localhost:3000"
	cookieName = "better-auth.better-auth-passkey"
)

// newServer starts goauth with the passkey plugin; BaseURL http://localhost:3000 makes rpID "localhost".
func newServer(t *testing.T, cfg pkconfig.PasskeyConfig, mut ...func(*config.AuthConfig)) (*compattest.Server, *passkey.Plugin) {
	t.Helper()
	p := passkey.New(cfg)
	s := compattest.NewServer(t, compattest.WithPlugin(p), compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = appOrigin
		c.User.DeleteUser.Enabled = true
		for _, m := range mut {
			m(c)
		}
	}))
	return s, p
}

// withJar returns a second browser on the same server (own cookie jar).
func withJar(s *compattest.Server) *compattest.Server {
	c := *s
	jar, _ := cookiejar.New(nil)
	c.Jar = jar
	c.Client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &c
}

func signUp(t *testing.T, s *compattest.Server, email string) string {
	t.Helper()
	r := s.Post(t, base+"/sign-up/email", map[string]any{"email": email, "password": "password1234", "name": "Test User"})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up: %d %s", r.Status, r.Body)
	}
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(t, &out)
	return out.User.ID
}

type errBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func expectErr(t *testing.T, r *compattest.Response, status int, code string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("expected %d %s, got %d %s", status, code, r.Status, r.Body)
	}
	var e errBody
	r.JSON(t, &e)
	if e.Code != code {
		t.Fatalf("expected code %s, got %s (%s)", code, e.Code, r.Body)
	}
}

func challengeOf(t *testing.T, r *compattest.Response) string {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("options: %d %s", r.Status, r.Body)
	}
	var o struct {
		Challenge string `json:"challenge"`
	}
	r.JSON(t, &o)
	return o.Challenge
}

// registerPasskey runs the whole registration ceremony and returns the stored passkey.
func registerPasskey(t *testing.T, s *compattest.Server, a *softAuthenticator, name string) map[string]any {
	t.Helper()
	ch := challengeOf(t, s.Get(t, base+"/passkey/generate-register-options"))
	body := map[string]any{"response": a.register(t, ch)}
	if name != "" {
		body["name"] = name
	}
	r := s.Post(t, base+"/passkey/verify-registration", body)
	if r.Status != http.StatusOK {
		t.Fatalf("verify-registration: %d %s", r.Status, r.Body)
	}
	var pk map[string]any
	r.JSON(t, &pk)
	return pk
}

func signInPasskey(t *testing.T, s *compattest.Server, a *softAuthenticator) *compattest.Response {
	t.Helper()
	ch := challengeOf(t, s.Get(t, base+"/passkey/generate-authenticate-options"))
	return s.Post(t, base+"/passkey/verify-authentication", map[string]any{"response": a.assert(t, ch)})
}

func dbPasskeys(t *testing.T, s *compattest.Server, userID string) []pkmodels.Passkey {
	t.Helper()
	var out []pkmodels.Passkey
	if err := s.DB.Where("user_id = ?", userID).Find(&out).Error; err != nil {
		t.Fatal(err)
	}
	return out
}

// ─── Options ─────────────────────────────────────────────────────────────────

func TestRegisterOptionsShape(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})

	// without a session registration is refused
	r := s.Get(t, base+"/passkey/generate-register-options")
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d %s", r.Status, r.Body)
	}

	signUp(t, s, "opts@example.com")
	r = s.Get(t, base+"/passkey/generate-register-options?authenticatorAttachment=platform&name=laptop")
	if r.Status != http.StatusOK {
		t.Fatalf("options: %d %s", r.Status, r.Body)
	}
	var o map[string]any
	r.JSON(t, &o)

	ch, _ := o["challenge"].(string)
	if raw, err := base64.RawURLEncoding.DecodeString(ch); err != nil || len(raw) != 32 {
		t.Fatalf("challenge must be 32 bytes base64url: %q", ch)
	}
	rp := o["rp"].(map[string]any)
	if rp["id"] != "localhost" || rp["name"] != "Better Auth" {
		t.Fatalf("rp = %v", rp)
	}
	user := o["user"].(map[string]any)
	if user["name"] != "laptop" || user["displayName"] != "opts@example.com" {
		t.Fatalf("user = %v", user)
	}
	if uid, err := base64.RawURLEncoding.DecodeString(user["id"].(string)); err != nil || len(uid) != 32 {
		t.Fatalf("user.id must be base64url of 32 chars: %v", user["id"])
	}
	params := o["pubKeyCredParams"].([]any)
	if len(params) != 3 || params[0].(map[string]any)["alg"].(float64) != -8 || params[1].(map[string]any)["alg"].(float64) != -7 || params[2].(map[string]any)["alg"].(float64) != -257 {
		t.Fatalf("pubKeyCredParams = %v", params)
	}
	if o["timeout"].(float64) != 60000 || o["attestation"] != "none" {
		t.Fatalf("timeout/attestation = %v %v", o["timeout"], o["attestation"])
	}
	sel := o["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "preferred" || sel["userVerification"] != "preferred" || sel["authenticatorAttachment"] != "platform" || sel["requireResidentKey"] != false {
		t.Fatalf("authenticatorSelection = %v", sel)
	}
	if ext := o["extensions"].(map[string]any); ext["credProps"] != true {
		t.Fatalf("extensions = %v", ext)
	}
	if ex, ok := o["excludeCredentials"].([]any); !ok || len(ex) != 0 {
		t.Fatalf("excludeCredentials = %v", o["excludeCredentials"])
	}
	if h, ok := o["hints"].([]any); !ok || len(h) != 0 {
		t.Fatalf("hints = %v", o["hints"])
	}
	ck := r.Cookie(cookieName)
	if ck == nil || ck.MaxAge != 300 || !ck.HttpOnly || ck.Value == "" {
		t.Fatalf("challenge cookie = %+v", ck)
	}
}

func TestRegisterOptionsConfig(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{
		RPID: "example.com", RPName: "My App",
		AuthenticatorSelection: &pkconfig.AuthenticatorSelection{ResidentKey: "required", UserVerification: "required", AuthenticatorAttachment: "cross-platform"},
		Registration:           pkconfig.RegistrationConfig{Extensions: map[string]any{"largeBlob": map[string]any{"support": "preferred"}}},
		Advanced:               pkconfig.AdvancedConfig{WebAuthnChallengeCookie: "pk-challenge"},
	})
	signUp(t, s, "cfg@example.com")
	r := s.Get(t, base+"/passkey/generate-register-options")
	var o map[string]any
	r.JSON(t, &o)
	if rp := o["rp"].(map[string]any); rp["id"] != "example.com" || rp["name"] != "My App" {
		t.Fatalf("rp = %v", rp)
	}
	sel := o["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "required" || sel["requireResidentKey"] != true || sel["userVerification"] != "required" || sel["authenticatorAttachment"] != "cross-platform" {
		t.Fatalf("authenticatorSelection = %v", sel)
	}
	ext := o["extensions"].(map[string]any)
	if ext["credProps"] != true || ext["largeBlob"] == nil {
		t.Fatalf("extensions = %v", ext)
	}
	if r.Cookie("better-auth.pk-challenge") == nil {
		t.Fatalf("custom challenge cookie missing: %v", r.Header.Values("Set-Cookie"))
	}
}

func TestAuthenticateOptionsShape(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})

	// anonymous: discoverable credentials, no allowCredentials
	r := s.Get(t, base+"/passkey/generate-authenticate-options")
	var o map[string]any
	r.JSON(t, &o)
	if o["rpId"] != "localhost" || o["userVerification"] != "preferred" || o["timeout"].(float64) != 60000 {
		t.Fatalf("options = %v", o)
	}
	if _, ok := o["allowCredentials"]; ok {
		t.Fatalf("anonymous options must not list credentials: %v", o)
	}
	if _, ok := o["extensions"]; ok {
		t.Fatalf("extensions must be omitted when unset: %v", o)
	}
	if r.Cookie(cookieName) == nil {
		t.Fatal("challenge cookie missing")
	}

	// with a session: the user's passkeys are listed with their transports
	signUp(t, s, "auth-opts@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)
	registerPasskey(t, s, a, "")
	r = s.Get(t, base+"/passkey/generate-authenticate-options")
	o = nil
	r.JSON(t, &o)
	allow := o["allowCredentials"].([]any)
	if len(allow) != 1 {
		t.Fatalf("allowCredentials = %v", allow)
	}
	c := allow[0].(map[string]any)
	if c["id"] != a.credentialID() || c["type"] != "public-key" || len(c["transports"].([]any)) != 2 {
		t.Fatalf("allowCredentials[0] = %v", c)
	}
}

// ─── Registration ────────────────────────────────────────────────────────────

func TestRegistrationStoresBetterAuthRow(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	uid := signUp(t, s, "reg@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)

	pk := registerPasskey(t, s, a, "  My Laptop  ")
	for _, k := range []string{"id", "name", "publicKey", "userId", "credentialID", "counter", "deviceType", "backedUp", "transports", "createdAt", "aaguid"} {
		if _, ok := pk[k]; !ok {
			t.Fatalf("response misses %q: %v", k, pk)
		}
	}
	if pk["name"] != "My Laptop" || pk["userId"] != uid || pk["credentialID"] != a.credentialID() || pk["counter"].(float64) != 0 ||
		pk["deviceType"] != "singleDevice" || pk["backedUp"] != false || pk["transports"] != "internal,hybrid" ||
		pk["aaguid"] != "adce0002-35bc-c60a-648b-0b25f1f05503" {
		t.Fatalf("passkey = %v", pk)
	}

	// publicKey is standard base64 of the COSE key
	rows := dbPasskeys(t, s, uid)
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	raw, err := base64.StdEncoding.DecodeString(rows[0].PublicKey)
	if err != nil {
		t.Fatalf("publicKey is not std base64: %v", err)
	}
	var cose map[int]any
	if err := cbor.Unmarshal(raw, &cose); err != nil || cose[3] != int64(-7) {
		t.Fatalf("publicKey is not the COSE key: %v %v", err, cose)
	}

	// the new credential is excluded from the next registration
	r := s.Get(t, base+"/passkey/generate-register-options")
	var o map[string]any
	r.JSON(t, &o)
	ex := o["excludeCredentials"].([]any)
	if len(ex) != 1 || ex[0].(map[string]any)["id"] != a.credentialID() {
		t.Fatalf("excludeCredentials = %v", ex)
	}
}

func TestRegistrationWithoutNameAndBackupFlags(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	signUp(t, s, "noname@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)
	a.flags |= flagBE | flagBS
	pk := registerPasskey(t, s, a, "")
	if pk["name"] != nil || pk["deviceType"] != "multiDevice" || pk["backedUp"] != true {
		t.Fatalf("passkey = %v", pk)
	}
}

func TestRegistrationRejections(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	signUp(t, s, "reject@example.com")

	cases := []struct {
		name   string
		mutate func(a *softAuthenticator, ch string) map[string]any
		status int
	}{
		{"wrong challenge", func(a *softAuthenticator, _ string) map[string]any {
			return a.register(t, base64.RawURLEncoding.EncodeToString([]byte("not-the-challenge-not-the-challe")))
		}, 500},
		{"wrong origin", func(a *softAuthenticator, ch string) map[string]any {
			a.origin = "https://evil.example"
			return a.register(t, ch)
		}, 500},
		{"wrong rpID", func(a *softAuthenticator, ch string) map[string]any {
			a.rpID = "evil.example"
			return a.register(t, ch)
		}, 500},
		{"user not present", func(a *softAuthenticator, ch string) map[string]any { a.flags = 0; return a.register(t, ch) }, 500},
		{"backed up single device", func(a *softAuthenticator, ch string) map[string]any { a.flags |= flagBS; return a.register(t, ch) }, 500},
		{"id/rawId mismatch", func(a *softAuthenticator, ch string) map[string]any {
			r := a.register(t, ch)
			r["id"] = "AAAA"
			return r
		}, 500},
		{"wrong ceremony type", func(a *softAuthenticator, ch string) map[string]any {
			r := a.register(t, ch)
			r["response"].(map[string]any)["clientDataJSON"] = b64url.EncodeToString(clientData("webauthn.get", ch, appOrigin))
			return r
		}, 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newSoftAuthenticator(t, "localhost", appOrigin)
			ch := challengeOf(t, s.Get(t, base+"/passkey/generate-register-options"))
			r := s.Post(t, base+"/passkey/verify-registration", map[string]any{"response": tc.mutate(a, ch)})
			expectErr(t, r, tc.status, "FAILED_TO_VERIFY_REGISTRATION")
		})
	}
}

func TestRegistrationChallengeIsSingleUse(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	signUp(t, s, "replay@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)

	ch := challengeOf(t, s.Get(t, base+"/passkey/generate-register-options"))
	resp := a.register(t, ch)
	if r := s.Post(t, base+"/passkey/verify-registration", map[string]any{"response": resp}); r.Status != 200 {
		t.Fatalf("first: %d %s", r.Status, r.Body)
	}
	// replaying the same response (same cookie) finds no challenge
	expectErr(t, s.Post(t, base+"/passkey/verify-registration", map[string]any{"response": resp}), 400, "CHALLENGE_NOT_FOUND")

	// no cookie at all
	other := withJar(s)
	signUp(t, other, "replay2@example.com")
	expectErr(t, other.Post(t, base+"/passkey/verify-registration", map[string]any{"response": resp}), 400, "CHALLENGE_NOT_FOUND")

	// a tampered (unsigned) cookie is ignored
	tampered := other.Post(t, base+"/passkey/verify-registration", map[string]any{"response": resp}, map[string]string{"Cookie": cookieName + "=forged"})
	if tampered.Status != 400 && tampered.Status != 401 {
		t.Fatalf("tampered cookie: %d %s", tampered.Status, tampered.Body)
	}
}

func TestRegistrationForAnotherUserRejected(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	signUp(t, s, "alice@example.com")
	// Alice's challenge cookie is carried to Bob's session
	r := s.Get(t, base+"/passkey/generate-register-options")
	ch := challengeOf(t, r)
	bob := withJar(s)
	signUp(t, bob, "bob@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)
	ck := r.Cookie(cookieName)
	req := bob.Post(t, base+"/passkey/verify-registration", map[string]any{"response": a.register(t, ch)}, map[string]string{"Cookie": bobCookies(bob) + "; " + ck.Name + "=" + ck.Value})
	expectErr(t, req, 401, "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY")
}

// bobCookies renders the jar's cookies of the server URL as a Cookie header.
func bobCookies(s *compattest.Server) string {
	req, _ := http.NewRequest(http.MethodGet, s.URL, nil)
	var parts []string
	for _, c := range s.Jar.Cookies(req.URL) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func TestRegistrationOriginConfig(t *testing.T) {
	// the configured origin list wins over the request's Origin header
	s, _ := newServer(t, pkconfig.PasskeyConfig{Origin: []string{"https://app.example", "https://other.example"}})
	signUp(t, s, "origin@example.com")
	a := newSoftAuthenticator(t, "localhost", "https://other.example")
	registerPasskey(t, s, a, "")

	b := newSoftAuthenticator(t, "localhost", appOrigin)
	ch := challengeOf(t, s.Get(t, base+"/passkey/generate-register-options"))
	expectErr(t, s.Post(t, base+"/passkey/verify-registration", map[string]any{"response": b.register(t, ch)}), 500, "FAILED_TO_VERIFY_REGISTRATION")
}

func TestRegistrationRequireSessionFalse(t *testing.T) {
	var gotContext *string
	s, _ := newServer(t, pkconfig.PasskeyConfig{Registration: pkconfig.RegistrationConfig{
		RequireSession: pkconfig.Bool(false),
		ResolveUser: func(ctx context.Context, in pkconfig.ResolveUserInput) (*pkconfig.RegistrationUser, error) {
			gotContext = in.Context
			if in.Context == nil {
				return &pkconfig.RegistrationUser{}, nil
			}
			return &pkconfig.RegistrationUser{ID: *in.Context, Name: "pre@example.com"}, nil
		},
	}})
	// a user exists, but the browser is not signed in
	other := withJar(s)
	uid := signUp(t, other, "pre@example.com")

	// resolveUser returning an invalid user
	expectErr(t, s.Get(t, base+"/passkey/generate-register-options"), 400, "RESOLVED_USER_INVALID")

	r := s.Get(t, base+"/passkey/generate-register-options?context="+uid)
	if gotContext == nil || *gotContext != uid {
		t.Fatalf("context not forwarded: %v", gotContext)
	}
	var o map[string]any
	r.JSON(t, &o)
	if o["user"].(map[string]any)["name"] != "pre@example.com" {
		t.Fatalf("user = %v", o["user"])
	}
	a := newSoftAuthenticator(t, "localhost", appOrigin)
	res := s.Post(t, base+"/passkey/verify-registration", map[string]any{"response": a.register(t, o["challenge"].(string))})
	if res.Status != 200 {
		t.Fatalf("verify: %d %s", res.Status, res.Body)
	}
	if rows := dbPasskeys(t, s, uid); len(rows) != 1 {
		t.Fatalf("passkey not stored for resolved user: %d", len(rows))
	}
	// the passkey signs the user in
	if r := signInPasskey(t, s, a); r.Status != 200 {
		t.Fatalf("sign-in: %d %s", r.Status, r.Body)
	}
}

func TestRegistrationResolveUserRequired(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{Registration: pkconfig.RegistrationConfig{RequireSession: pkconfig.Bool(false)}})
	expectErr(t, s.Get(t, base+"/passkey/generate-register-options"), 400, "RESOLVE_USER_REQUIRED")
}

func TestRegistrationAfterVerificationHook(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{Registration: pkconfig.RegistrationConfig{
		AfterVerification: func(ctx context.Context, v pkconfig.RegistrationVerification) (*pkconfig.RegistrationResult, error) {
			if v.CredentialID == "" || len(v.PublicKey) == 0 || v.User.ID == "" {
				t.Errorf("hook input = %+v", v)
			}
			return &pkconfig.RegistrationResult{Name: "From Hook"}, nil
		},
	}})
	signUp(t, s, "hook@example.com")
	pk := registerPasskey(t, s, newSoftAuthenticator(t, "localhost", appOrigin), "")
	if pk["name"] != "From Hook" {
		t.Fatalf("name = %v", pk["name"])
	}
	// an explicit name wins over the hook's
	pk = registerPasskey(t, s, newSoftAuthenticator(t, "localhost", appOrigin), "Explicit")
	if pk["name"] != "Explicit" {
		t.Fatalf("name = %v", pk["name"])
	}
}

// ─── Authentication ──────────────────────────────────────────────────────────

func TestAuthenticationSignsIn(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	uid := signUp(t, s, "signin@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)
	a.counterStep = 1
	registerPasskey(t, s, a, "key")

	// sign out, then sign back in with the passkey from a fresh browser
	s.Post(t, base+"/sign-out", map[string]any{})
	fresh := withJar(s)
	r := signInPasskey(t, fresh, a)
	if r.Status != http.StatusOK {
		t.Fatalf("verify-authentication: %d %s", r.Status, r.Body)
	}
	var out struct {
		Session struct {
			Token  string `json:"token"`
			UserID string `json:"userId"`
		} `json:"session"`
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	r.JSON(t, &out)
	if out.User.ID != uid || out.Session.UserID != uid || out.Session.Token == "" || out.User.Email != "signin@example.com" {
		t.Fatalf("response = %s", r.Body)
	}
	if ck := r.Cookie("better-auth.session_token"); ck == nil || ck.Value == "" {
		t.Fatalf("session cookie missing: %v", r.Header.Values("Set-Cookie"))
	}

	// the session works
	gs := fresh.Get(t, base+"/get-session")
	var sess struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	gs.JSON(t, &sess)
	if sess.User.ID != uid {
		t.Fatalf("get-session = %s", gs.Body)
	}

	// the counter was stored
	if rows := dbPasskeys(t, s, uid); rows[0].Counter != 1 {
		t.Fatalf("counter = %d", rows[0].Counter)
	}
	// signing in again with a higher counter works
	if r := signInPasskey(t, fresh, a); r.Status != 200 {
		t.Fatalf("second sign-in: %d %s", r.Status, r.Body)
	}
	if rows := dbPasskeys(t, s, uid); rows[0].Counter != 2 {
		t.Fatalf("counter = %d", rows[0].Counter)
	}
}

func TestAuthenticationZeroCounterAllowed(t *testing.T) {
	// authenticators that never increment (counter always 0) keep working
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	signUp(t, s, "zero@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)
	registerPasskey(t, s, a, "")
	for i := 0; i < 2; i++ {
		if r := signInPasskey(t, withJar(s), a); r.Status != 200 {
			t.Fatalf("sign-in %d: %d %s", i, r.Status, r.Body)
		}
	}
}

func TestAuthenticationCounterRegression(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	signUp(t, s, "counter@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)
	registerPasskey(t, s, a, "")
	a.counter = 5
	if r := signInPasskey(t, withJar(s), a); r.Status != 200 {
		t.Fatalf("sign-in: %d %s", r.Status, r.Body)
	}
	// a cloned authenticator replays a lower (or equal) counter
	a.counter = 3
	expectErr(t, signInPasskey(t, withJar(s), a), 400, "AUTHENTICATION_FAILED")
	a.counter = 5
	expectErr(t, signInPasskey(t, withJar(s), a), 400, "AUTHENTICATION_FAILED")
}

func TestAuthenticationRejections(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	signUp(t, s, "authrej@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)
	registerPasskey(t, s, a, "")

	t.Run("unknown credential", func(t *testing.T) {
		b := newSoftAuthenticator(t, "localhost", appOrigin)
		expectErr(t, signInPasskey(t, withJar(s), b), 401, "PASSKEY_NOT_FOUND")
	})
	t.Run("bad signature", func(t *testing.T) {
		// same credential ID, different key
		b := newSoftAuthenticator(t, "localhost", appOrigin)
		b.credID = a.credID
		expectErr(t, signInPasskey(t, withJar(s), b), 401, "AUTHENTICATION_FAILED")
	})
	t.Run("wrong origin", func(t *testing.T) {
		b := *a
		b.origin = "https://evil.example"
		expectErr(t, signInPasskey(t, withJar(s), &b), 400, "AUTHENTICATION_FAILED")
	})
	t.Run("wrong rpID", func(t *testing.T) {
		b := *a
		b.rpID = "evil.example"
		expectErr(t, signInPasskey(t, withJar(s), &b), 400, "AUTHENTICATION_FAILED")
	})
	t.Run("wrong challenge", func(t *testing.T) {
		c := withJar(s)
		challengeOf(t, c.Get(t, base+"/passkey/generate-authenticate-options"))
		resp := a.assert(t, base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		expectErr(t, c.Post(t, base+"/passkey/verify-authentication", map[string]any{"response": resp}), 400, "AUTHENTICATION_FAILED")
	})
	t.Run("no challenge cookie", func(t *testing.T) {
		expectErr(t, withJar(s).Post(t, base+"/passkey/verify-authentication", map[string]any{"response": a.assert(t, "x")}), 400, "CHALLENGE_NOT_FOUND")
	})
	t.Run("replayed challenge", func(t *testing.T) {
		c := withJar(s)
		ch := challengeOf(t, c.Get(t, base+"/passkey/generate-authenticate-options"))
		resp := a.assert(t, ch)
		if r := c.Post(t, base+"/passkey/verify-authentication", map[string]any{"response": resp}); r.Status != 200 {
			t.Fatalf("first: %d %s", r.Status, r.Body)
		}
		expectErr(t, c.Post(t, base+"/passkey/verify-authentication", map[string]any{"response": resp}), 400, "CHALLENGE_NOT_FOUND")
	})
	t.Run("user not present", func(t *testing.T) {
		b := *a
		b.flags = 0
		expectErr(t, signInPasskey(t, withJar(s), &b), 400, "AUTHENTICATION_FAILED")
	})
}

func TestAuthenticationAfterVerificationVeto(t *testing.T) {
	vetoed := pkconfig.Bool(true)
	s, _ := newServer(t, pkconfig.PasskeyConfig{Authentication: pkconfig.AuthenticationConfig{
		AfterVerification: func(ctx context.Context, v pkconfig.AuthenticationVerification) error {
			if *vetoed {
				return errVeto
			}
			return nil
		},
	}})
	signUp(t, s, "veto@example.com")
	a := newSoftAuthenticator(t, "localhost", appOrigin)
	registerPasskey(t, s, a, "")
	expectErr(t, signInPasskey(t, withJar(s), a), 403, "VETO")
	*vetoed = false
	if r := signInPasskey(t, withJar(s), a); r.Status != 200 {
		t.Fatalf("sign-in: %d %s", r.Status, r.Body)
	}
}

// ─── Management ──────────────────────────────────────────────────────────────

func TestListUpdateDeleteOwnership(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	alice := s
	aliceID := signUp(t, alice, "alice-m@example.com")
	pk := registerPasskey(t, alice, newSoftAuthenticator(t, "localhost", appOrigin), "first")
	registerPasskey(t, alice, newSoftAuthenticator(t, "localhost", appOrigin), "second")
	id := pk["id"].(string)

	bob := withJar(s)
	signUp(t, bob, "bob-m@example.com")
	registerPasskey(t, bob, newSoftAuthenticator(t, "localhost", appOrigin), "bob")

	// list returns only the caller's passkeys
	var list []map[string]any
	alice.Get(t, base+"/passkey/list-user-passkeys").JSON(t, &list)
	if len(list) != 2 || list[0]["userId"] != aliceID || list[0]["name"] != "first" {
		t.Fatalf("list = %v", list)
	}
	list = nil
	bob.Get(t, base+"/passkey/list-user-passkeys").JSON(t, &list)
	if len(list) != 1 {
		t.Fatalf("bob list = %v", list)
	}

	// anonymous callers are refused
	anon := withJar(s)
	if r := anon.Get(t, base+"/passkey/list-user-passkeys"); r.Status != 401 {
		t.Fatalf("anonymous list: %d", r.Status)
	}
	if r := anon.Post(t, base+"/passkey/delete-passkey", map[string]any{"id": id}); r.Status != 401 {
		t.Fatalf("anonymous delete: %d", r.Status)
	}

	// Bob cannot touch Alice's passkey
	expectErr(t, bob.Post(t, base+"/passkey/update-passkey", map[string]any{"id": id, "name": "pwned"}), 401, "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY")
	expectErr(t, bob.Post(t, base+"/passkey/delete-passkey", map[string]any{"id": id}), 401, "UNAUTHORIZED")

	// unknown / empty IDs and invalid names
	expectErr(t, alice.Post(t, base+"/passkey/update-passkey", map[string]any{"id": "nope", "name": "x"}), 404, "PASSKEY_NOT_FOUND")
	expectErr(t, alice.Post(t, base+"/passkey/delete-passkey", map[string]any{"id": "nope"}), 404, "PASSKEY_NOT_FOUND")
	expectErr(t, alice.Post(t, base+"/passkey/delete-passkey", map[string]any{"id": ""}), 400, "BAD_REQUEST")
	expectErr(t, alice.Post(t, base+"/passkey/update-passkey", map[string]any{"id": id, "name": "   "}), 400, "VALIDATION_ERROR")
	if r := alice.Post(t, base+"/passkey/update-passkey", map[string]any{"id": id}); r.Status != 400 {
		t.Fatalf("missing name: %d %s", r.Status, r.Body)
	}

	// Alice renames and deletes her passkey
	r := alice.Post(t, base+"/passkey/update-passkey", map[string]any{"id": id, "name": "  renamed "})
	var upd struct {
		Passkey map[string]any `json:"passkey"`
	}
	r.JSON(t, &upd)
	if r.Status != 200 || upd.Passkey["name"] != "renamed" || upd.Passkey["id"] != id {
		t.Fatalf("update: %d %s", r.Status, r.Body)
	}
	r = alice.Post(t, base+"/passkey/delete-passkey", map[string]any{"id": id})
	var st struct {
		Status bool `json:"status"`
	}
	r.JSON(t, &st)
	if r.Status != 200 || !st.Status {
		t.Fatalf("delete: %d %s", r.Status, r.Body)
	}
	if rows := dbPasskeys(t, s, aliceID); len(rows) != 1 {
		t.Fatalf("rows after delete = %d", len(rows))
	}
}

func TestUserDeletionRemovesPasskeys(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{})
	uid := signUp(t, s, "delete@example.com")
	registerPasskey(t, s, newSoftAuthenticator(t, "localhost", appOrigin), "")
	registerPasskey(t, s, newSoftAuthenticator(t, "localhost", appOrigin), "")
	other := withJar(s)
	otherID := signUp(t, other, "keep@example.com")
	registerPasskey(t, other, newSoftAuthenticator(t, "localhost", appOrigin), "")

	if r := s.Post(t, base+"/delete-user", map[string]any{}); r.Status != 200 {
		t.Fatalf("delete-user: %d %s", r.Status, r.Body)
	}
	if rows := dbPasskeys(t, s, uid); len(rows) != 0 {
		t.Fatalf("passkeys left after user deletion: %d", len(rows))
	}
	if rows := dbPasskeys(t, s, otherID); len(rows) != 1 {
		t.Fatalf("other user's passkeys touched: %d", len(rows))
	}
}

func TestDisabledPaths(t *testing.T) {
	s, _ := newServer(t, pkconfig.PasskeyConfig{}, func(c *config.AuthConfig) {
		c.DisabledPaths = []string{"/passkey/delete-passkey"}
	})
	signUp(t, s, "disabled@example.com")
	if r := s.Post(t, base+"/passkey/delete-passkey", map[string]any{"id": "x"}); r.Status != 404 && r.Status != 405 {
		t.Fatalf("disabled path answered %d", r.Status)
	}
}

var errVeto = pluginkit.NewError(http.StatusForbidden, "VETO", "sign-in vetoed")
