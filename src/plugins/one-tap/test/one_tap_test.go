package test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	onetap "github.com/better-go-auth/goauth/src/plugins/one-tap"
	onetapconfig "github.com/better-go-auth/goauth/src/plugins/one-tap/config"
	"github.com/better-go-auth/goauth/src/plugins/one-tap/services"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const (
	googleClientID = "google-client-id.apps.googleusercontent.com"
	googleIssuer   = "https://accounts.google.com"
)

// env is a goauth server with the one-tap plugin verifying tokens against a fake Google JWKS.
type env struct {
	s      *compattest.Server
	google *socialtest.Provider
	plugin *onetap.Plugin
}

type envOpts struct {
	oneTap []onetap.Option
	core   func(*config.AuthConfig)
	// withSocial also installs the social plugin with a "google" provider (client ID googleClientID)
	withSocial bool
	socialCfg  func(*socialconfig.SocialConfig)
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	// Step 1: the fake Google (JWKS + ID token signer), issuing tokens like accounts.google.com
	google := socialtest.New(googleClientID, "secret")
	google.Issuer = googleIssuer
	t.Cleanup(google.Close)
	// Step 2: the plugins
	opts := append([]onetap.Option{onetap.WithJWKSURL(google.JWKSEndpoint())}, o.oneTap...)
	serverOpts := []compattest.Option{compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = "http://localhost:3000"
		c.TrustedOrigins = append(c.TrustedOrigins, "http://localhost:*")
		if o.core != nil {
			o.core(c)
		}
	})}
	if o.withSocial {
		sc := socialconfig.SocialConfig{Providers: []providers.Provider{
			providers.Google(providers.GoogleOptions{ProviderOptions: providers.ProviderOptions{ClientID: googleClientID, ClientSecret: "secret"}}),
		}}
		if o.socialCfg != nil {
			o.socialCfg(&sc)
		}
		sp := social.New(sc)
		opts = append(opts, onetap.WithSocialPlugin(sp))
		serverOpts = append(serverOpts, compattest.WithPlugin(sp))
	}
	p := onetap.New(onetapconfig.OneTapConfig{}, opts...)
	serverOpts = append(serverOpts, compattest.WithPlugin(p))
	return &env{s: compattest.NewServer(t, serverOpts...), google: google, plugin: p}
}

func (e *env) token(prof socialtest.Profile, extra map[string]any) string {
	return e.google.SignIDToken(prof, "", extra)
}

func (e *env) callback(t *testing.T, idToken string) *compattest.Response {
	t.Helper()
	return e.s.Post(t, "/api/auth/one-tap/callback", map[string]any{"idToken": idToken})
}

type callbackBody struct {
	Token string `json:"token"`
	Error string `json:"error"`
	User  struct {
		ID            string  `json:"id"`
		Email         string  `json:"email"`
		Name          string  `json:"name"`
		Image         *string `json:"image"`
		EmailVerified bool    `json:"emailVerified"`
	} `json:"user"`
}

func errBody(t *testing.T, r *compattest.Response) (code, message string) {
	t.Helper()
	var b struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	r.JSON(t, &b)
	return b.Code, b.Message
}

var alice = socialtest.Profile{Sub: "google-sub-1", Email: "Alice@Example.com", EmailVerified: true, Name: "Alice", Picture: "https://img.example.com/a.png"}

func TestOneTap_SignUpThenSignIn(t *testing.T) {
	e := newEnv(t, envOpts{oneTap: []onetap.Option{onetap.WithClientID(googleClientID)}})
	idToken := e.token(alice, nil)

	// Step 1: an unknown Google account signs up: {token, user} + session cookie
	r := e.callback(t, idToken)
	if r.Status != http.StatusOK {
		t.Fatalf("callback: %d %s", r.Status, r.Body)
	}
	var body callbackBody
	r.JSON(t, &body)
	if body.Token == "" || body.User.Email != "alice@example.com" || body.User.Name != "Alice" || !body.User.EmailVerified {
		t.Fatalf("body = %s", r.Body)
	}
	if body.User.Image == nil || *body.User.Image != alice.Picture {
		t.Fatalf("image = %v", body.User.Image)
	}
	if c := r.Cookie("better-auth.session_token"); c == nil || c.Value == "" {
		t.Fatalf("no session cookie: %v", r.Header.Values("Set-Cookie"))
	}
	// the JSON has exactly better-auth's keys
	var raw map[string]any
	_ = json.Unmarshal(r.Body, &raw)
	if _, ok := raw["error"]; ok || len(raw) != 2 {
		t.Fatalf("keys = %v", raw)
	}

	// Step 2: the cookie is a working session
	var sess struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	gs := e.s.Get(t, "/api/auth/get-session")
	gs.JSON(t, &sess)
	if sess.User.Email != "alice@example.com" {
		t.Fatalf("get-session = %s", gs.Body)
	}

	// Step 3: the account is a "google" account holding the ID token and better-auth's scope
	var acc models.Account
	if err := e.s.DB.Where("user_id = ? AND provider_id = ?", body.User.ID, "google").First(&acc).Error; err != nil {
		t.Fatalf("account: %v", err)
	}
	if acc.AccountID != alice.Sub || acc.IDToken == nil || *acc.IDToken != idToken || acc.Scope == nil || *acc.Scope != services.Scope {
		t.Fatalf("account = %+v", acc)
	}

	// Step 4: the same Google account signs in again: same user, still one account
	r2 := e.callback(t, e.token(alice, nil))
	var body2 callbackBody
	r2.JSON(t, &body2)
	if r2.Status != http.StatusOK || body2.User.ID != body.User.ID || body2.Token == body.Token {
		t.Fatalf("second callback: %d %s", r2.Status, r2.Body)
	}
	var n int64
	e.s.DB.Model(&models.Account{}).Where("user_id = ?", body.User.ID).Count(&n)
	if n != 1 {
		t.Fatalf("accounts = %d, want 1", n)
	}
}

func TestOneTap_InvalidTokens(t *testing.T) {
	e := newEnv(t, envOpts{oneTap: []onetap.Option{onetap.WithClientID(googleClientID)}})
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"garbage":         "not-a-jwt",
		"wrong signature": e.google.SignIDTokenWithKey(other, alice, "", nil),
		"wrong audience":  e.token(alice, map[string]any{"aud": "someone-else"}),
		"wrong issuer":    e.token(alice, map[string]any{"iss": "https://evil.example.com"}),
		"expired":         e.token(alice, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
		"unknown kid":     unknownKid(e),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			r := e.callback(t, tok)
			code, msg := errBody(t, r)
			if r.Status != http.StatusBadRequest || code != "BAD_REQUEST" || msg != "invalid id token" {
				t.Fatalf("%d %s", r.Status, r.Body)
			}
			if r.Cookie("better-auth.session_token") != nil {
				t.Fatal("session cookie set for an invalid token")
			}
		})
	}
	// the issuer without scheme is accepted, like better-auth
	if r := e.callback(t, e.token(alice, map[string]any{"iss": "accounts.google.com"})); r.Status != http.StatusOK {
		t.Fatalf("accounts.google.com issuer: %d %s", r.Status, r.Body)
	}
	// a missing idToken is a validation error
	if r := e.s.Post(t, "/api/auth/one-tap/callback", map[string]any{}); r.Status != http.StatusBadRequest {
		t.Fatalf("missing idToken: %d %s", r.Status, r.Body)
	}
}

// unknownKid signs a token whose kid is not in the JWKS.
func unknownKid(e *env) string {
	kid := e.google.KID
	e.google.KID = "other-kid"
	defer func() { e.google.KID = kid }()
	return e.token(alice, nil)
}

func TestOneTap_NoEmail(t *testing.T) {
	e := newEnv(t, envOpts{oneTap: []onetap.Option{onetap.WithClientID(googleClientID)}})
	// better-auth answers 200 {error} and creates nothing
	r := e.callback(t, e.token(socialtest.Profile{Sub: "no-email", Name: "Nobody"}, nil))
	if r.Status != http.StatusOK || string(r.Body) != "{\"error\":\"Email not available in token\"}\n" {
		t.Fatalf("%d %q", r.Status, r.Body)
	}
	if r.Cookie("better-auth.session_token") != nil {
		t.Fatal("cookie set without email")
	}
	var n int64
	e.s.DB.Model(&models.User{}).Count(&n)
	if n != 0 {
		t.Fatalf("users = %d", n)
	}
}

func TestOneTap_DisableSignup(t *testing.T) {
	e := newEnv(t, envOpts{oneTap: []onetap.Option{onetap.WithClientID(googleClientID), onetap.WithDisableSignup(true)}})
	// Step 1: unknown account → 401 "signup disabled"
	r := e.callback(t, e.token(alice, nil))
	code, msg := errBody(t, r)
	if r.Status != http.StatusUnauthorized || code != "UNAUTHORIZED" || msg != "signup disabled" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// Step 2: an existing user (email/password) still signs in with a verified Google email
	signUp := e.s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "alice@example.com", "password": "Password123!", "name": "Alice"})
	if signUp.Status != http.StatusOK {
		t.Fatalf("sign-up: %d %s", signUp.Status, signUp.Body)
	}
	e.s.DB.Model(&models.User{}).Where("email = ?", "alice@example.com").Update("email_verified", true)
	if r := e.callback(t, e.token(alice, nil)); r.Status != http.StatusOK {
		t.Fatalf("existing user with signup disabled: %d %s", r.Status, r.Body)
	}
}

func TestOneTap_ImplicitLinking(t *testing.T) {
	e := newEnv(t, envOpts{oneTap: []onetap.Option{onetap.WithClientID(googleClientID)}})
	// Step 1: an email/password user with a verified email
	signUp := e.s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "alice@example.com", "password": "Password123!", "name": "Alice"})
	if signUp.Status != http.StatusOK {
		t.Fatalf("sign-up: %d %s", signUp.Status, signUp.Body)
	}
	e.s.DB.Model(&models.User{}).Where("email = ?", "alice@example.com").Update("email_verified", true)

	// Step 2: Google says the email is not verified → "account not linked"
	r := e.callback(t, e.token(alice, map[string]any{"email_verified": false}))
	code, msg := errBody(t, r)
	if r.Status != http.StatusUnauthorized || code != "UNAUTHORIZED" || msg != "account not linked" {
		t.Fatalf("unverified: %d %s", r.Status, r.Body)
	}
	// the string "false" is not verified either (toBoolean)
	if r := e.callback(t, e.token(alice, map[string]any{"email_verified": "false"})); r.Status != http.StatusUnauthorized {
		t.Fatalf("string false: %d %s", r.Status, r.Body)
	}

	// Step 3: the string "true" counts as verified: the Google account is linked to the existing user
	r = e.callback(t, e.token(alice, map[string]any{"email_verified": "true"}))
	if r.Status != http.StatusOK {
		t.Fatalf("string true: %d %s", r.Status, r.Body)
	}
	var body callbackBody
	r.JSON(t, &body)
	var accounts []models.Account
	e.s.DB.Where("user_id = ?", body.User.ID).Find(&accounts)
	providers := map[string]bool{}
	for _, a := range accounts {
		providers[string(a.ProviderID)] = true
	}
	if len(accounts) != 2 || !providers["credential"] || !providers["google"] {
		t.Fatalf("accounts = %+v", accounts)
	}
}

func TestOneTap_SocialPluginSettings(t *testing.T) {
	// Step 1: no ClientID: the social plugin's google client ID is the audience
	e := newEnv(t, envOpts{withSocial: true, socialCfg: func(c *socialconfig.SocialConfig) {
		c.AccountLinking.Enabled = socialconfig.Bool(false)
	}})
	if got := e.plugin.Service().ClientID(); got != googleClientID {
		t.Fatalf("ClientID() = %q", got)
	}
	if r := e.callback(t, e.token(alice, map[string]any{"aud": "other"})); r.Status != http.StatusBadRequest {
		t.Fatalf("other audience: %d %s", r.Status, r.Body)
	}
	if r := e.callback(t, e.token(alice, nil)); r.Status != http.StatusOK {
		t.Fatalf("social client id: %d %s", r.Status, r.Body)
	}
	// Step 2: the social plugin's account linking policy applies (linking disabled → not linked)
	e.s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "bob@example.com", "password": "Password123!", "name": "Bob"})
	e.s.DB.Model(&models.User{}).Where("email = ?", "bob@example.com").Update("email_verified", true)
	r := e.callback(t, e.token(socialtest.Profile{Sub: "bob-sub", Email: "bob@example.com", EmailVerified: true, Name: "Bob"}, nil))
	if _, msg := errBody(t, r); r.Status != http.StatusUnauthorized || msg != "account not linked" {
		t.Fatalf("linking disabled: %d %s", r.Status, r.Body)
	}
}

func TestOneTap_NoAudienceConfigured(t *testing.T) {
	// without any client ID the audience is not checked (better-auth's jwtVerify with audience undefined)
	e := newEnv(t, envOpts{})
	if r := e.callback(t, e.token(alice, map[string]any{"aud": "anything"})); r.Status != http.StatusOK {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestOneTap_DisabledAndOriginCheck(t *testing.T) {
	// Step 1: DisabledOps removes the route
	e := newEnv(t, envOpts{oneTap: []onetap.Option{onetap.WithClientID(googleClientID)}, core: func(c *config.AuthConfig) {
		c.DisabledOps = []consts.OperationId{"oneTapCallback"}
	}})
	if r := e.callback(t, e.token(alice, nil)); r.Status != http.StatusNotFound {
		t.Fatalf("disabled: %d %s", r.Status, r.Body)
	}
	// Step 2: a request with cookies from an untrusted origin is refused before the token is checked
	e2 := newEnv(t, envOpts{oneTap: []onetap.Option{onetap.WithClientID(googleClientID)}})
	r := e2.s.Post(t, "/api/auth/one-tap/callback", map[string]any{"idToken": e2.token(alice, nil)},
		map[string]string{"Origin": "https://evil.example.com", "Cookie": "a=b"})
	if code, _ := errBody(t, r); r.Status != http.StatusForbidden || code != "INVALID_ORIGIN" {
		t.Fatalf("untrusted origin: %d %s", r.Status, r.Body)
	}
}

func TestOneTap_ConcurrentFirstSignIn(t *testing.T) {
	e := newEnv(t, envOpts{oneTap: []onetap.Option{onetap.WithClientID(googleClientID)}})
	// several tabs completing One Tap at once end with one user
	var wg sync.WaitGroup
	statuses := make([]int, 5)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			jar, _ := cookiejar.New(nil)
			s := *e.s
			s.Client = &http.Client{Jar: jar}
			statuses[i] = s.Post(t, "/api/auth/one-tap/callback", map[string]any{"idToken": e.token(alice, nil)}).Status
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, st := range statuses {
		if st == http.StatusOK {
			ok++
		}
	}
	if ok == 0 {
		t.Fatalf("statuses = %v", statuses)
	}
	var n int64
	e.s.DB.Model(&models.User{}).Where("email = ?", "alice@example.com").Count(&n)
	if n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
}
