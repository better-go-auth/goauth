package test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	goauth "github.com/better-go-auth/goauth"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	magiclink "github.com/better-go-auth/goauth/src/plugins/magic-link"
	mlconfig "github.com/better-go-auth/goauth/src/plugins/magic-link/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const (
	signInPath = "/api/auth/sign-in/magic-link"
	verifyPath = "/api/auth/magic-link/verify"
	appOrigin  = "http://localhost:3000"
)

// ─── Test helpers ────────────────────────────────────────────────────────────

// sink records every SendMagicLink call.
type sink struct {
	mu    sync.Mutex
	calls []mlconfig.SendMagicLinkData
	err   error
}

func (k *sink) send(data mlconfig.SendMagicLinkData, _ *http.Request) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, data)
	return k.err
}

func (k *sink) last(t *testing.T) mlconfig.SendMagicLinkData {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.calls) == 0 {
		t.Fatal("SendMagicLink was not called")
	}
	return k.calls[len(k.calls)-1]
}

func (k *sink) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.calls)
}

type env struct {
	s    *compattest.Server
	sink *sink
}

// newEnv starts a goauth server with the magic-link plugin; extra server options are appended.
func newEnv(t *testing.T, cfg mlconfig.MagicLinkConfig, opts []magiclink.Option, extra ...compattest.Option) *env {
	t.Helper()
	k := &sink{}
	if cfg.SendMagicLink == nil {
		cfg.SendMagicLink = k.send
	}
	all := []compattest.Option{
		compattest.WithPlugin(magiclink.New(cfg, opts...)),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = appOrigin
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	}
	all = append(all, extra...)
	return &env{s: compattest.NewServer(t, all...), sink: k}
}

// signIn requests a link for email and returns the captured data.
func (e *env) signIn(t *testing.T, body map[string]any) mlconfig.SendMagicLinkData {
	t.Helper()
	res := e.s.Post(t, signInPath, body)
	if res.Status != http.StatusOK {
		t.Fatalf("sign-in: status %d: %s", res.Status, res.Body)
	}
	var out map[string]any
	res.JSON(t, &out)
	if out["status"] != true {
		t.Fatalf("sign-in: expected {status:true}, got %s", res.Body)
	}
	return e.sink.last(t)
}

// verifyPathFromURL turns the absolute link into a path on the test server.
func verifyPathFromURL(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("bad link %q: %v", link, err)
	}
	return u.Path + "?" + u.RawQuery
}

func expectCode(t *testing.T, res *compattest.Response, status int, code string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("expected status %d, got %d: %s", status, res.Status, res.Body)
	}
	var body map[string]any
	res.JSON(t, &body)
	if body["code"] != code {
		t.Fatalf("expected code %s, got %s", code, res.Body)
	}
}

func expectRedirect(t *testing.T, res *compattest.Response, location string) {
	t.Helper()
	if res.Status != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", res.Status, res.Body)
	}
	if got := res.Header.Get("Location"); got != location {
		t.Fatalf("expected Location %q, got %q", location, got)
	}
}

func sessionCookie(res *compattest.Response) *http.Cookie {
	for _, c := range (&http.Response{Header: res.Header}).Cookies() {
		if strings.HasSuffix(c.Name, "session_token") && c.Value != "" {
			return c
		}
	}
	return nil
}

func findVerification(t *testing.T, s *compattest.Server, identifier string) *models.Verification {
	t.Helper()
	var v models.Verification
	if err := s.DB.Where(&models.Verification{Identifier: identifier}).First(&v).Error; err != nil {
		return nil
	}
	return &v
}

func countUsers(t *testing.T, s *compattest.Server, email string) int64 {
	t.Helper()
	var n int64
	s.DB.Model(&models.User{}).Where(&models.User{UserDto: models.UserDto{Email: email}}).Count(&n)
	return n
}

func findUser(t *testing.T, s *compattest.Server, email string) *models.User {
	t.Helper()
	var u models.User
	if err := s.DB.Where(&models.User{UserDto: models.UserDto{Email: email}}).First(&u).Error; err != nil {
		t.Fatalf("user %s not found: %v", email, err)
	}
	return &u
}

func createUser(t *testing.T, s *compattest.Server, email string, verified bool) *models.User {
	t.Helper()
	u := &models.User{UserDto: models.UserDto{Name: "Existing", Email: email, EmailVerified: verified, Role: "user"}}
	if err := s.DB.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ─── Sign-in request ─────────────────────────────────────────────────────────

func TestSignInBuildsBetterAuthURL(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	data := e.signIn(t, map[string]any{
		"email":              "url@example.com",
		"name":               "Url User",
		"callbackURL":        "/dashboard",
		"newUserCallbackURL": "/welcome",
		"errorCallbackURL":   "/error",
		"metadata":           map[string]any{"inviteId": "abc", "n": 1},
	})

	// token: 32 letters (generateRandomString(32, "a-z", "A-Z"))
	if !regexp.MustCompile(`^[a-zA-Z]{32}$`).MatchString(data.Token) {
		t.Fatalf("unexpected token format %q", data.Token)
	}
	want := appOrigin + "/api/auth/magic-link/verify?token=" + data.Token +
		"&callbackURL=%2Fdashboard&newUserCallbackURL=%2Fwelcome&errorCallbackURL=%2Ferror"
	if data.URL != want {
		t.Fatalf("url mismatch\n got %s\nwant %s", data.URL, want)
	}
	if data.Email != "url@example.com" {
		t.Fatalf("email: %q", data.Email)
	}
	if data.Metadata["inviteId"] != "abc" || data.Metadata["n"] != float64(1) {
		t.Fatalf("metadata not forwarded: %#v", data.Metadata)
	}

	// storage: identifier = token, value = {"email","name"}, expires in 5 minutes
	v := findVerification(t, e.s, data.Token)
	if v == nil {
		t.Fatal("verification row not stored under the plain token")
	}
	if v.Value != `{"email":"url@example.com","name":"Url User"}` {
		t.Fatalf("value: %s", v.Value)
	}
	if d := time.Until(v.ExpiresAt); d < 4*time.Minute || d > 5*time.Minute+5*time.Second {
		t.Fatalf("expiresAt not ~5 minutes away: %v", d)
	}
}

func TestSignInDefaultsCallbackURLAndOmitsName(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	data := e.signIn(t, map[string]any{"email": "plain@example.com"})
	want := appOrigin + "/api/auth/magic-link/verify?token=" + data.Token + "&callbackURL=%2F"
	if data.URL != want {
		t.Fatalf("url mismatch\n got %s\nwant %s", data.URL, want)
	}
	if v := findVerification(t, e.s, data.Token); v == nil || v.Value != `{"email":"plain@example.com"}` {
		t.Fatalf("value without name: %+v", v)
	}
	if data.Metadata != nil {
		t.Fatalf("metadata should be nil, got %#v", data.Metadata)
	}
}

func TestSignInURLUsesCustomBasePath(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil, compattest.WithConfig(func(c *config.AuthConfig) {
		c.BasePath = "/auth"
	}))
	res := e.s.Post(t, "/auth/sign-in/magic-link", map[string]any{"email": "bp@example.com"})
	if res.Status != http.StatusOK {
		t.Fatalf("status %d: %s", res.Status, res.Body)
	}
	data := e.sink.last(t)
	if !strings.HasPrefix(data.URL, appOrigin+"/auth/magic-link/verify?token=") {
		t.Fatalf("url %s", data.URL)
	}
	if res := e.s.Get(t, verifyPathFromURL(t, data.URL)); res.Status != http.StatusFound {
		t.Fatalf("verify on custom base path: %d %s", res.Status, res.Body)
	}
}

func TestSignInInvalidEmail(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	for _, email := range []string{"not-an-email", "a@b", "@example.com", "a..b@example.com", ""} {
		expectCode(t, e.s.Post(t, signInPath, map[string]any{"email": email}), http.StatusBadRequest, "INVALID_EMAIL")
	}
	if e.sink.count() != 0 {
		t.Fatal("no link must be sent for invalid emails")
	}
}

func TestSignInRejectsUntrustedCallbackURLs(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	cases := map[string]string{
		"callbackURL":        "INVALID_CALLBACK_URL",
		"errorCallbackURL":   "INVALID_ERROR_CALLBACK_URL",
		"newUserCallbackURL": "INVALID_NEW_USER_CALLBACK_URL",
	}
	for field, code := range cases {
		res := e.s.Post(t, signInPath, map[string]any{"email": "cb@example.com", field: "https://evil.example.com/x"})
		expectCode(t, res, http.StatusForbidden, code)
	}
	if e.sink.count() != 0 {
		t.Fatal("no link must be sent for untrusted callbacks")
	}
	// trusted absolute URLs and relative paths are accepted
	e.signIn(t, map[string]any{"email": "cb@example.com", "callbackURL": appOrigin + "/ok", "errorCallbackURL": "/err"})
}

func TestSignInSenderErrorIsReturned(t *testing.T) {
	k := &sink{err: autherr.New("SEND_FAILED", "could not send", http.StatusBadGateway)}
	e := newEnv(t, mlconfig.MagicLinkConfig{SendMagicLink: k.send}, nil)
	expectCode(t, e.s.Post(t, signInPath, map[string]any{"email": "fail@example.com"}), http.StatusBadGateway, "SEND_FAILED")

	k.err = errors.New("smtp down")
	res := e.s.Post(t, signInPath, map[string]any{"email": "fail@example.com"})
	if res.Status != http.StatusInternalServerError {
		t.Fatalf("plain sender errors must be 500, got %d", res.Status)
	}
}

// ─── Verify ──────────────────────────────────────────────────────────────────

func TestVerifyJSONResponseSignsUpNewUser(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	data := e.signIn(t, map[string]any{"email": "New.User@Example.com", "name": "New User"})

	// no callbackURL query → JSON {token, user, session}
	res := e.s.Get(t, verifyPath+"?token="+data.Token)
	if res.Status != http.StatusOK {
		t.Fatalf("verify: %d %s", res.Status, res.Body)
	}
	var body struct {
		Token string         `json:"token"`
		User  map[string]any `json:"user"`
		Sess  map[string]any `json:"session"`
	}
	res.JSON(t, &body)
	if body.Token == "" || body.Sess["token"] != body.Token {
		t.Fatalf("token mismatch: %s", res.Body)
	}
	if body.User["email"] != "new.user@example.com" || body.User["name"] != "New User" || body.User["emailVerified"] != true {
		t.Fatalf("user: %s", res.Body)
	}
	if body.Sess["userId"] != body.User["id"] {
		t.Fatalf("session.userId != user.id: %s", res.Body)
	}
	for _, key := range []string{"id", "createdAt", "updatedAt", "image"} {
		if _, ok := body.User[key]; !ok {
			t.Fatalf("user.%s missing: %s", key, res.Body)
		}
	}
	for _, key := range []string{"id", "expiresAt", "ipAddress", "userAgent", "createdAt", "updatedAt"} {
		if _, ok := body.Sess[key]; !ok {
			t.Fatalf("session.%s missing: %s", key, res.Body)
		}
	}
	if c := sessionCookie(res); c == nil || !strings.HasPrefix(c.Value, body.Token) {
		t.Fatalf("session cookie not set: %v", res.Header.Values("Set-Cookie"))
	}

	// the user exists, verified, without an account row
	u := findUser(t, e.s, "new.user@example.com")
	if !u.EmailVerified || u.Name != "New User" {
		t.Fatalf("stored user: %+v", u.UserDto)
	}
	var accounts int64
	e.s.DB.Model(&models.Account{}).Where(&models.Account{UserID: u.ID}).Count(&accounts)
	if accounts != 0 {
		t.Fatalf("magic link sign-up must not create accounts, got %d", accounts)
	}

	// the cookie authenticates get-session
	gs := e.s.Get(t, "/api/auth/get-session")
	var sess map[string]any
	gs.JSON(t, &sess)
	if user, _ := sess["user"].(map[string]any); user == nil || user["id"] != u.ID {
		t.Fatalf("get-session: %s", gs.Body)
	}
}

func TestVerifyNewUserWithoutNameGetsEmptyName(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	data := e.signIn(t, map[string]any{"email": "noname@example.com"})
	if res := e.s.Get(t, verifyPathFromURL(t, data.URL)); res.Status != http.StatusFound {
		t.Fatalf("verify: %d %s", res.Status, res.Body)
	}
	if u := findUser(t, e.s, "noname@example.com"); u.Name != "" || !u.EmailVerified {
		t.Fatalf("user: %+v", u.UserDto)
	}
}

func TestVerifyRedirectsWithCookie(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	data := e.signIn(t, map[string]any{"email": "redir@example.com", "callbackURL": "/dashboard"})
	res := e.s.Get(t, verifyPathFromURL(t, data.URL))
	expectRedirect(t, res, appOrigin+"/dashboard")
	if sessionCookie(res) == nil {
		t.Fatal("redirect must carry the session cookie")
	}
}

func TestVerifyNewUserCallbackOnlyForNewUsers(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	body := map[string]any{"email": "nu@example.com", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"}

	// first sign-in creates the user → newUserCallbackURL
	data := e.signIn(t, body)
	expectRedirect(t, e.s.Get(t, verifyPathFromURL(t, data.URL)), appOrigin+"/welcome")

	// second sign-in finds the user → callbackURL, no duplicate user
	data = e.signIn(t, body)
	expectRedirect(t, e.s.Get(t, verifyPathFromURL(t, data.URL)), appOrigin+"/dashboard")
	if n := countUsers(t, e.s, "nu@example.com"); n != 1 {
		t.Fatalf("expected 1 user, got %d", n)
	}
}

func TestVerifyExistingUserSignIn(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	existing := createUser(t, e.s, "known@example.com", true)
	// the email is matched case-insensitively and the stored name is not overwritten
	data := e.signIn(t, map[string]any{"email": "Known@Example.com", "name": "Other Name"})
	res := e.s.Get(t, verifyPath+"?token="+data.Token)
	if res.Status != http.StatusOK {
		t.Fatalf("verify: %d %s", res.Status, res.Body)
	}
	var body map[string]any
	res.JSON(t, &body)
	if user := body["user"].(map[string]any); user["id"] != existing.ID || user["name"] != "Existing" {
		t.Fatalf("expected the existing user: %s", res.Body)
	}
	if n := countUsers(t, e.s, "known@example.com"); n != 1 {
		t.Fatalf("expected 1 user, got %d", n)
	}
}

func TestVerifyMarksExistingUnverifiedUserVerified(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	createUser(t, e.s, "unverified@example.com", false)
	data := e.signIn(t, map[string]any{"email": "unverified@example.com"})
	res := e.s.Get(t, verifyPath+"?token="+data.Token)
	var body map[string]any
	res.JSON(t, &body)
	if body["user"].(map[string]any)["emailVerified"] != true {
		t.Fatalf("response user not verified: %s", res.Body)
	}
	if !findUser(t, e.s, "unverified@example.com").EmailVerified {
		t.Fatal("stored user not verified")
	}
}

func TestVerifyTokenIsSingleUse(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	data := e.signIn(t, map[string]any{"email": "once@example.com", "callbackURL": "/dashboard"})
	link := verifyPathFromURL(t, data.URL)
	expectRedirect(t, e.s.Get(t, link), appOrigin+"/dashboard")
	if findVerification(t, e.s, data.Token) != nil {
		t.Fatal("verification row must be deleted after use")
	}
	// second use → error redirect to callbackURL (the default errorCallbackURL)
	expectRedirect(t, e.s.Get(t, link), appOrigin+"/dashboard?error=INVALID_TOKEN")
}

func TestVerifyErrorRedirects(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	// unknown token without any callback → base URL root
	expectRedirect(t, e.s.Get(t, verifyPath+"?token=nope"), appOrigin+"/?error=INVALID_TOKEN")
	// errorCallbackURL wins over callbackURL
	expectRedirect(t, e.s.Get(t, verifyPath+"?token=nope&callbackURL=%2Fdash&errorCallbackURL=%2Foops"), appOrigin+"/oops?error=INVALID_TOKEN")
	// existing query parameters are kept
	got := e.s.Get(t, verifyPath+"?token=nope&errorCallbackURL="+url.QueryEscape(appOrigin+"/oops?a=1"))
	loc, _ := url.Parse(got.Header.Get("Location"))
	if got.Status != http.StatusFound || loc.Path != "/oops" || loc.Query().Get("a") != "1" || loc.Query().Get("error") != "INVALID_TOKEN" {
		t.Fatalf("unexpected redirect %d %s", got.Status, got.Header.Get("Location"))
	}
	// missing token is a validation error
	if res := e.s.Get(t, verifyPath); res.Status < 400 || res.Status >= 500 {
		t.Fatalf("missing token: %d", res.Status)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	data := e.signIn(t, map[string]any{"email": "late@example.com", "callbackURL": "/dashboard", "errorCallbackURL": "/expired"})
	e.s.DB.Model(&models.Verification{}).Where(&models.Verification{Identifier: data.Token}).
		Update("ExpiresAt", time.Now().Add(-time.Minute).UTC())
	expectRedirect(t, e.s.Get(t, verifyPathFromURL(t, data.URL)), appOrigin+"/expired?error=INVALID_TOKEN")
	if countUsers(t, e.s, "late@example.com") != 0 {
		t.Fatal("expired token must not create a user")
	}
}

func TestVerifyExpiresInOption(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, []magiclink.Option{magiclink.WithExpiresIn(time.Hour)})
	data := e.signIn(t, map[string]any{"email": "hour@example.com"})
	v := findVerification(t, e.s, data.Token)
	if d := time.Until(v.ExpiresAt); d < 59*time.Minute || d > time.Hour+5*time.Second {
		t.Fatalf("expiresAt not ~1h away: %v", d)
	}
}

func TestVerifyRejectsUntrustedCallbackURLs(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	data := e.signIn(t, map[string]any{"email": "evil@example.com"})
	evil := url.QueryEscape("https://evil.example.com/steal")
	// better-auth labels all three verify checks "callbackURL"
	for _, param := range []string{"callbackURL", "newUserCallbackURL", "errorCallbackURL"} {
		res := e.s.Get(t, verifyPath+"?token="+data.Token+"&"+param+"="+evil)
		expectCode(t, res, http.StatusForbidden, "INVALID_CALLBACK_URL")
	}
	// the token was not consumed by the rejected requests
	if findVerification(t, e.s, data.Token) == nil {
		t.Fatal("rejected requests must not consume the token")
	}
	// double-encoded untrusted targets are decoded before the check
	res := e.s.Get(t, verifyPath+"?token="+data.Token+"&callbackURL="+url.QueryEscape(evil))
	expectCode(t, res, http.StatusForbidden, "INVALID_CALLBACK_URL")
}

func TestVerifyAbsoluteTrustedCallback(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	data := e.signIn(t, map[string]any{"email": "abs@example.com", "callbackURL": "http://localhost:4000/app?x=1"})
	expectRedirect(t, e.s.Get(t, verifyPathFromURL(t, data.URL)), "http://localhost:4000/app?x=1")
}

// ─── Token options ───────────────────────────────────────────────────────────

func TestHashedTokenStorage(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{StoreToken: mlconfig.StoreTokenConfig{Mode: mlconfig.StoreTokenHashed}}, nil)
	data := e.signIn(t, map[string]any{"email": "hashed@example.com"})
	if findVerification(t, e.s, data.Token) != nil {
		t.Fatal("plain token must not be stored")
	}
	if findVerification(t, e.s, hashToken(data.Token)) == nil {
		t.Fatal("identifier must be base64url(sha256(token)) without padding")
	}
	if res := e.s.Get(t, verifyPath+"?token="+data.Token); res.Status != http.StatusOK {
		t.Fatalf("verify hashed: %d %s", res.Status, res.Body)
	}
	// the hash itself is not a valid token
	data = e.signIn(t, map[string]any{"email": "hashed@example.com"})
	expectRedirect(t, e.s.Get(t, verifyPath+"?token="+hashToken(data.Token)), appOrigin+"/?error=INVALID_TOKEN")
}

func TestCustomHasherTokenStorage(t *testing.T) {
	hash := func(token string) (string, error) { return "custom:" + strings.ToUpper(token), nil }
	e := newEnv(t, mlconfig.MagicLinkConfig{StoreToken: mlconfig.StoreTokenConfig{Hash: hash}}, nil)
	data := e.signIn(t, map[string]any{"email": "custom@example.com"})
	if findVerification(t, e.s, "custom:"+strings.ToUpper(data.Token)) == nil {
		t.Fatal("identifier must be the custom hash")
	}
	if res := e.s.Get(t, verifyPath+"?token="+data.Token); res.Status != http.StatusOK {
		t.Fatalf("verify custom: %d %s", res.Status, res.Body)
	}
}

func TestGenerateTokenOverride(t *testing.T) {
	gen := func(email string) string { return "tok-" + strings.ReplaceAll(email, "@", "-at-") }
	e := newEnv(t, mlconfig.MagicLinkConfig{}, []magiclink.Option{magiclink.WithGenerateToken(gen)})
	data := e.signIn(t, map[string]any{"email": "gen@example.com"})
	if data.Token != "tok-gen-at-example.com" || !strings.Contains(data.URL, "token=tok-gen-at-example.com&") {
		t.Fatalf("custom token not used: %+v", data)
	}
	if findVerification(t, e.s, data.Token) == nil {
		t.Fatal("custom token not stored")
	}
	if res := e.s.Get(t, verifyPath+"?token="+data.Token); res.Status != http.StatusOK {
		t.Fatalf("verify: %d %s", res.Status, res.Body)
	}
}

// ─── Sign-up control, bans, hooks ────────────────────────────────────────────

func TestDisableSignUp(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{DisableSignUp: true}, nil)
	data := e.signIn(t, map[string]any{"email": "stranger@example.com", "callbackURL": "/dashboard"})
	expectRedirect(t, e.s.Get(t, verifyPathFromURL(t, data.URL)), appOrigin+"/dashboard?error=new_user_signup_disabled")
	if countUsers(t, e.s, "stranger@example.com") != 0 {
		t.Fatal("user must not be created")
	}
	// existing users can still sign in
	createUser(t, e.s, "member@example.com", true)
	data = e.signIn(t, map[string]any{"email": "member@example.com", "callbackURL": "/dashboard"})
	expectRedirect(t, e.s.Get(t, verifyPathFromURL(t, data.URL)), appOrigin+"/dashboard")
}

func TestBannedUserRejected(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil, func(o *goauth.GoAuthOptions) {
		p, err := admin.NewWithGorm(o.Conn)
		if err != nil {
			t.Fatal(err)
		}
		o.Plugins = append(o.Plugins, p)
	})
	u := createUser(t, e.s, "banned@example.com", true)
	e.s.DB.Model(&models.User{}).Where(&models.User{Base: models.Base{ID: u.ID}}).Update("Banned", true)
	data := e.signIn(t, map[string]any{"email": "banned@example.com"})
	expectCode(t, e.s.Get(t, verifyPath+"?token="+data.Token), http.StatusForbidden, "BANNED_USER")
}

// hookPlugin records user-creation hooks and can veto sign-ups.
type hookPlugin struct {
	plugins.DefaultHookService
	mu     sync.Mutex
	before []string
	after  []string
	veto   string
}

func (h *hookPlugin) ID() string                        { return "test-hooks" }
func (h *hookPlugin) Init(*plugins.InitContext) error   { return nil }
func (h *hookPlugin) Migrator() migration.IMigrator     { return nil }
func (h *hookPlugin) Services() map[string]any          { return nil }
func (h *hookPlugin) Routes() []plugins.RouteDescriptor { return nil }
func (h *hookPlugin) Hooks() plugins.HookService        { return h }
func (h *hookPlugin) BeforeUserCreate(_ context.Context, u *models.User) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.before = append(h.before, u.Email)
	if u.Email == h.veto {
		return autherr.New("SIGNUP_VETOED", "vetoed", http.StatusForbidden)
	}
	u.Image = ptr("https://img.example.com/" + u.Email)
	return nil
}
func (h *hookPlugin) AfterUserCreate(_ context.Context, u *models.User) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.after = append(h.after, u.ID)
	return nil
}

func ptr(s string) *string { return &s }

func TestUserCreationHooksFire(t *testing.T) {
	hp := &hookPlugin{veto: "vetoed@example.com"}
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil, compattest.WithPlugin(hp))

	data := e.signIn(t, map[string]any{"email": "hooked@example.com"})
	res := e.s.Get(t, verifyPath+"?token="+data.Token)
	if res.Status != http.StatusOK {
		t.Fatalf("verify: %d %s", res.Status, res.Body)
	}
	var body map[string]any
	res.JSON(t, &body)
	if img := body["user"].(map[string]any)["image"]; img != "https://img.example.com/hooked@example.com" {
		t.Fatalf("BeforeUserCreate change not applied: %v", img)
	}
	if len(hp.before) != 1 || len(hp.after) != 1 {
		t.Fatalf("hooks: before=%v after=%v", hp.before, hp.after)
	}

	// signing in again does not create a user, so hooks do not run
	data = e.signIn(t, map[string]any{"email": "hooked@example.com"})
	e.s.Get(t, verifyPath+"?token="+data.Token)
	if len(hp.before) != 1 || len(hp.after) != 1 {
		t.Fatalf("hooks ran for an existing user: before=%v after=%v", hp.before, hp.after)
	}

	// a vetoing hook's error is returned unchanged
	data = e.signIn(t, map[string]any{"email": "vetoed@example.com"})
	expectCode(t, e.s.Get(t, verifyPath+"?token="+data.Token), http.StatusForbidden, "SIGNUP_VETOED")
	if countUsers(t, e.s, "vetoed@example.com") != 0 {
		t.Fatal("vetoed user created")
	}
}

// ─── Rate limiting ───────────────────────────────────────────────────────────

func TestRateLimit(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil, compattest.WithConfig(func(c *config.AuthConfig) {
		c.RateLimit.Enabled = true
	}))
	// default rule: 5 requests per 60s
	for i := 0; i < 5; i++ {
		if res := e.s.Post(t, signInPath, map[string]any{"email": "rl@example.com"}); res.Status != http.StatusOK {
			t.Fatalf("request %d: %d %s", i+1, res.Status, res.Body)
		}
	}
	res := e.s.Post(t, signInPath, map[string]any{"email": "rl@example.com"})
	if res.Status != http.StatusTooManyRequests || res.Header.Get("X-Retry-After") == "" {
		t.Fatalf("expected 429 with X-Retry-After, got %d %v", res.Status, res.Header)
	}
	// verify has its own counter
	for i := 0; i < 5; i++ {
		if res := e.s.Get(t, verifyPath+"?token=x"); res.Status != http.StatusFound {
			t.Fatalf("verify %d: %d", i+1, res.Status)
		}
	}
	if res := e.s.Get(t, verifyPath+"?token=x"); res.Status != http.StatusTooManyRequests {
		t.Fatalf("verify: expected 429, got %d", res.Status)
	}
}

func TestRateLimitCustomRuleAndDisabled(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, []magiclink.Option{magiclink.WithRateLimit(time.Minute, 2)},
		compattest.WithConfig(func(c *config.AuthConfig) { c.RateLimit.Enabled = true }))
	for i := 0; i < 2; i++ {
		if res := e.s.Post(t, signInPath, map[string]any{"email": "rl2@example.com"}); res.Status != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, res.Status)
		}
	}
	if res := e.s.Post(t, signInPath, map[string]any{"email": "rl2@example.com"}); res.Status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", res.Status)
	}

	// without AuthConfig.RateLimit.Enabled nothing is limited
	off := newEnv(t, mlconfig.MagicLinkConfig{}, []magiclink.Option{magiclink.WithRateLimit(time.Minute, 1)})
	for i := 0; i < 4; i++ {
		if res := off.s.Post(t, signInPath, map[string]any{"email": "free@example.com"}); res.Status != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, res.Status)
		}
	}
}

// ─── Plugin wiring ───────────────────────────────────────────────────────────

func TestPluginRequiresSender(t *testing.T) {
	p := magiclink.New(mlconfig.MagicLinkConfig{})
	if err := p.Init(&plugins.InitContext{}); err == nil {
		t.Fatal("Init must fail without SendMagicLink")
	}
	custom := magiclink.New(mlconfig.MagicLinkConfig{
		SendMagicLink: func(mlconfig.SendMagicLinkData, *http.Request) error { return nil },
		StoreToken:    mlconfig.StoreTokenConfig{Mode: mlconfig.StoreTokenCustom},
	})
	if err := custom.Init(&plugins.InitContext{}); err == nil {
		t.Fatal("Init must fail for custom-hasher without Hash")
	}
	if p.ID() != "magic-link" || p.Migrator() != nil {
		t.Fatal("unexpected plugin identity")
	}
	cfg := p.Config()
	if cfg.ExpiresIn != 5*time.Minute || cfg.RateLimit.Window != time.Minute || cfg.RateLimit.Max != 5 || cfg.StoreToken.Mode != mlconfig.StoreTokenPlain {
		t.Fatalf("defaults: %+v", cfg)
	}
}

func TestDisabledPaths(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil, compattest.WithConfig(func(c *config.AuthConfig) {
		c.DisabledPaths = append(c.DisabledPaths, "/sign-in/magic-link")
	}))
	if res := e.s.Post(t, signInPath, map[string]any{"email": "x@example.com"}); res.Status != http.StatusNotFound && res.Status != http.StatusMethodNotAllowed {
		t.Fatalf("disabled path still served: %d", res.Status)
	}
}
