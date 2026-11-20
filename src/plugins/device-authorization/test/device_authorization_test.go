package test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	deviceauthorization "github.com/better-go-auth/goauth/src/plugins/device-authorization"
	daconfig "github.com/better-go-auth/goauth/src/plugins/device-authorization/config"
	"github.com/better-go-auth/goauth/src/plugins/device-authorization/dtos"
	"github.com/better-go-auth/goauth/src/plugins/device-authorization/services"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// ─── Harness ─────────────────────────────────────────────────────────────────

type harness struct {
	*compattest.Server
	plugin *deviceauthorization.Plugin
	clock  *fakeClock
}

// fakeClock is a settable clock for expiry and polling checks.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newHarness starts goauth with the device-authorization plugin (and the bearer plugin, so the issued
// access token works as a bearer token) and a fake clock.
func newHarness(t *testing.T, cfg daconfig.DeviceAuthorizationConfig, configure ...func(*config.AuthConfig)) *harness {
	t.Helper()
	p := deviceauthorization.New(cfg)
	noSig := false
	s := compattest.NewServer(t,
		compattest.WithPlugin(p),
		compattest.WithPlugin(bearer.New(bearerconfig.BearerConfig{RequireSignature: &noSig})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
			for _, fn := range configure {
				fn(c)
			}
		}),
	)
	// cookies are passed explicitly so several users can share one server
	s.Client.Jar = nil
	clock := &fakeClock{now: time.Now()}
	p.Service().SetClock(clock.Now)
	return &harness{Server: s, plugin: p, clock: clock}
}

type oauthErr struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type codeErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// expectOAuthError checks an {error, error_description} response.
func expectOAuthError(t *testing.T, r *compattest.Response, status int, code, desc string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s)", r.Status, status, r.Body)
	}
	var e oauthErr
	r.JSON(t, &e)
	if e.Error != code || (desc != "" && e.ErrorDescription != desc) {
		t.Fatalf("error = %+v, want %s / %q", e, code, desc)
	}
	if strings.Contains(string(r.Body), `"code"`) || strings.Contains(string(r.Body), `"message"`) {
		t.Fatalf("OAuth error has extra members: %s", r.Body)
	}
}

// expectValidation checks a 400 VALIDATION_ERROR with message.
func expectValidation(t *testing.T, r *compattest.Response, message string) {
	t.Helper()
	if r.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", r.Status, r.Body)
	}
	var e codeErr
	r.JSON(t, &e)
	if e.Code != "VALIDATION_ERROR" || (message != "" && e.Message != message) {
		t.Fatalf("error = %+v, want VALIDATION_ERROR %q", e, message)
	}
}

func expectOK(t *testing.T, r *compattest.Response) {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", r.Status, r.Body)
	}
}

// cookieHeader turns the response's non-expired Set-Cookie entries into a Cookie request header.
func cookieHeader(r *compattest.Response) string {
	var parts []string
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func withCookie(c string) map[string]string { return map[string]string{"Cookie": c} }

// signUp creates a user and returns its id and session cookies.
func (h *harness) signUp(t *testing.T, email string) (string, string) {
	t.Helper()
	r := h.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": "Password123!", "name": "User"})
	expectOK(t, r)
	var b struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	r.JSON(t, &b)
	return b.User.ID, cookieHeader(r)
}

// requestCode posts /device/code and decodes the response.
func (h *harness) requestCode(t *testing.T, body map[string]any) dtos.DeviceCodeResponse {
	t.Helper()
	r := h.Post(t, "/api/auth/device/code", body)
	expectOK(t, r)
	var res dtos.DeviceCodeResponse
	r.JSON(t, &res)
	return res
}

// poll posts /device/token.
func (h *harness) poll(t *testing.T, deviceCode, clientID string) *compattest.Response {
	t.Helper()
	return h.Post(t, "/api/auth/device/token", map[string]any{
		"grant_type": dtos.GrantTypeDeviceCode, "device_code": deviceCode, "client_id": clientID,
	})
}

// claimAndApprove signs the user's browser into the verification page and approves the code.
func (h *harness) claimAndApprove(t *testing.T, cookies, userCode string) {
	t.Helper()
	r := h.Get(t, "/api/auth/device?user_code="+url.QueryEscape(userCode), withCookie(cookies))
	expectOK(t, r)
	expectOK(t, h.Post(t, "/api/auth/device/approve", map[string]any{"userCode": userCode}, withCookie(cookies)))
}

// ─── POST /device/code ───────────────────────────────────────────────────────

func TestDeviceCodeResponse(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{})

	// Step 1: better-auth's defaults: 30 minutes, 5 seconds, 40 + 8 characters, /device on the base URL origin
	r := h.Post(t, "/api/auth/device/code", map[string]any{"client_id": "cli", "scope": "openid profile"})
	expectOK(t, r)
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", r.Header.Get("Cache-Control"))
	}
	var res dtos.DeviceCodeResponse
	r.JSON(t, &res)
	if res.ExpiresIn != 1800 || res.Interval != 5 {
		t.Fatalf("expires_in/interval = %d/%d", res.ExpiresIn, res.Interval)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]{40}$`).MatchString(res.DeviceCode) {
		t.Fatalf("device_code = %q", res.DeviceCode)
	}
	if !regexp.MustCompile(`^[` + daconfig.UserCodeCharset + `]{8}$`).MatchString(res.UserCode) {
		t.Fatalf("user_code = %q", res.UserCode)
	}
	if res.VerificationURI != "http://localhost:3000/device" ||
		res.VerificationURIComplete != "http://localhost:3000/device?user_code="+res.UserCode {
		t.Fatalf("verification URIs = %q / %q", res.VerificationURI, res.VerificationURIComplete)
	}

	// Step 2: the exact member set of the RFC 8628 response
	var raw map[string]any
	r.JSON(t, &raw)
	for _, k := range []string{"device_code", "user_code", "verification_uri", "verification_uri_complete", "expires_in", "interval"} {
		if _, ok := raw[k]; !ok {
			t.Fatalf("missing %s in %s", k, r.Body)
		}
	}
	if len(raw) != 6 {
		t.Fatalf("unexpected members: %s", r.Body)
	}

	// Step 3: the row is stored pending, with the client, scope and polling interval in milliseconds
	rec, err := h.plugin.Service().FindByUserCode(context.Background(), res.UserCode)
	if err != nil || rec == nil {
		t.Fatalf("row: %v %v", rec, err)
	}
	if rec.Status != dtos.StatusPending || rec.UserID != nil || *rec.ClientID != "cli" || *rec.Scope != "openid profile" ||
		*rec.PollingInterval != 5000 || rec.DeviceCode != res.DeviceCode {
		t.Fatalf("row = %+v", rec)
	}
}

func TestDeviceCodeOptions(t *testing.T) {
	var calls atomic.Int32
	var gotClient, gotScope string
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{
		ExpiresIn:          10 * time.Minute,
		Interval:           2 * time.Second,
		GenerateDeviceCode: func(context.Context) (string, error) { return "device-" + time.Now().Format("150405.000000000"), nil },
		GenerateUserCode:   func(context.Context) (string, error) { return "CUSTOM" + string(rune('A'+calls.Load())), nil },
		VerificationURI:    "https://app.example.com/activate?src=tv",
		OnDeviceAuthRequest: func(_ context.Context, clientID string, scope *string) error {
			calls.Add(1)
			gotClient = clientID
			if scope != nil {
				gotScope = *scope
			}
			return nil
		},
	})

	// Step 1: custom generators, lifetimes and an absolute verification URI with its own query
	res := h.requestCode(t, map[string]any{"client_id": "tv-app", "scope": "read"})
	if !strings.HasPrefix(res.DeviceCode, "device-") || res.UserCode != "CUSTOMB" || res.ExpiresIn != 600 || res.Interval != 2 {
		t.Fatalf("response = %+v", res)
	}
	if res.VerificationURI != "https://app.example.com/activate?src=tv" ||
		res.VerificationURIComplete != "https://app.example.com/activate?src=tv&user_code=CUSTOMB" {
		t.Fatalf("verification URIs = %q / %q", res.VerificationURI, res.VerificationURIComplete)
	}
	// Step 2: the hook saw the request
	if calls.Load() != 1 || gotClient != "tv-app" || gotScope != "read" {
		t.Fatalf("hook = %d %q %q", calls.Load(), gotClient, gotScope)
	}
}

func TestVerificationURIs(t *testing.T) {
	cases := map[string][2]string{
		"":                          {"http://localhost:3000/device", "http://localhost:3000/device?user_code=ABC"},
		"/custom-path":              {"http://localhost:3000/custom-path", "http://localhost:3000/custom-path?user_code=ABC"},
		"device":                    {"http://localhost:3000/api/device", "http://localhost:3000/api/device?user_code=ABC"},
		"https://example.com":       {"https://example.com/", "https://example.com/?user_code=ABC"},
		"https://example.com/d?x=1": {"https://example.com/d?x=1", "https://example.com/d?x=1&user_code=ABC"},
	}
	for uri, want := range cases {
		t.Run(uri, func(t *testing.T) {
			h := newHarness(t, daconfig.DeviceAuthorizationConfig{VerificationURI: uri})
			got, complete := h.plugin.Service().VerificationURIs(context.Background(), "ABC")
			if got != want[0] || complete != want[1] {
				t.Fatalf("got %q / %q, want %q / %q", got, complete, want[0], want[1])
			}
		})
	}
}

func TestDeviceCodeValidation(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{})
	expectValidation(t, h.Post(t, "/api/auth/device/code", map[string]any{}),
		"[body.client_id] Invalid input: expected string, received undefined")
	expectValidation(t, h.Post(t, "/api/auth/device/code", map[string]any{"client_id": 5}), "")
}

func TestOnDeviceAuthRequestError(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{
		OnDeviceAuthRequest: func(context.Context, string, *string) error {
			return services.OAuthError(http.StatusBadRequest, "invalid_scope", "Scope not allowed")
		},
	})
	expectOAuthError(t, h.Post(t, "/api/auth/device/code", map[string]any{"client_id": "x"}), 400, "invalid_scope", "Scope not allowed")
}

// ─── The full flow ───────────────────────────────────────────────────────────

func TestDeviceFlowApprove(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{})
	ctx := context.Background()

	// Step 1: the device asks for a code
	code := h.requestCode(t, map[string]any{"client_id": "cli", "scope": "openid"})

	// Step 2: polling before the user acts: pending, then slow_down when polling faster than the interval
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "authorization_pending", "Authorization pending")
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "slow_down", "Polling too frequently")
	h.clock.Advance(4 * time.Second)
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "slow_down", "Polling too frequently")
	h.clock.Advance(time.Second)
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "authorization_pending", "")

	// Step 3: the user opens the verification page signed in: the code is claimed for them
	userID, cookies := h.signUp(t, "device-user@example.com")
	r := h.Get(t, "/api/auth/device?user_code="+code.UserCode, withCookie(cookies))
	expectOK(t, r)
	var verify dtos.DeviceVerifyResponse
	r.JSON(t, &verify)
	if verify.UserCode != code.UserCode || verify.Status != dtos.StatusPending {
		t.Fatalf("verify = %+v", verify)
	}
	rec, _ := h.plugin.Service().FindByUserCode(ctx, code.UserCode)
	if rec.UserID == nil || *rec.UserID != userID {
		t.Fatalf("code not claimed: %+v", rec)
	}

	// Step 4: approve (the dashed display form works too)
	dashed := code.UserCode[:4] + "-" + code.UserCode[4:]
	r = h.Post(t, "/api/auth/device/approve", map[string]any{"userCode": dashed}, withCookie(cookies))
	expectOK(t, r)
	if strings.TrimSpace(string(r.Body)) != `{"success":true}` {
		t.Fatalf("approve body = %s", r.Body)
	}
	r = h.Get(t, "/api/auth/device?user_code="+dashed, withCookie(cookies))
	expectOK(t, r)
	r.JSON(t, &verify)
	if verify.UserCode != dashed || verify.Status != dtos.StatusApproved {
		t.Fatalf("verify after approve = %+v", verify)
	}

	// Step 5: the next poll gets the session token
	h.clock.Advance(5 * time.Second)
	r = h.poll(t, code.DeviceCode, "cli")
	expectOK(t, r)
	if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("headers = %v", r.Header)
	}
	if r.Header.Get("Set-Cookie") != "" {
		t.Fatalf("token response sets cookies: %v", r.Header.Values("Set-Cookie"))
	}
	var tok dtos.DeviceTokenResponse
	r.JSON(t, &tok)
	if tok.AccessToken == "" || tok.TokenType != "Bearer" || tok.Scope != "openid" || tok.ExpiresIn < 6*24*3600 {
		t.Fatalf("token = %+v", tok)
	}

	// Step 6: the token is a session token: get-session with it as bearer returns the user
	r = h.Get(t, "/api/auth/get-session", map[string]string{"Authorization": "Bearer " + tok.AccessToken})
	expectOK(t, r)
	var sess struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		Session struct {
			Token string `json:"token"`
		} `json:"session"`
	}
	r.JSON(t, &sess)
	if sess.User.ID != userID || sess.Session.Token != tok.AccessToken {
		t.Fatalf("session = %+v", sess)
	}

	// Step 7: the device code is single use
	h.clock.Advance(5 * time.Second)
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "invalid_grant", "Invalid device code")
	if rec, _ := h.plugin.Service().FindByUserCode(ctx, code.UserCode); rec != nil {
		t.Fatalf("row kept: %+v", rec)
	}
}

func TestDeviceFlowDeny(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{})
	code := h.requestCode(t, map[string]any{"client_id": "cli"})
	_, cookies := h.signUp(t, "deny@example.com")

	// Step 1: claim, then deny
	expectOK(t, h.Get(t, "/api/auth/device?user_code="+code.UserCode, withCookie(cookies)))
	r := h.Post(t, "/api/auth/device/deny", map[string]any{"userCode": code.UserCode}, withCookie(cookies))
	expectOK(t, r)

	// Step 2: a second decision is refused
	expectOAuthError(t, h.Post(t, "/api/auth/device/approve", map[string]any{"userCode": code.UserCode}, withCookie(cookies)),
		400, "invalid_request", "Device code already processed")
	expectOAuthError(t, h.Post(t, "/api/auth/device/deny", map[string]any{"userCode": code.UserCode}, withCookie(cookies)),
		400, "invalid_request", "Device code already processed")

	// Step 3: the device learns about the denial once; the code is gone afterwards
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "access_denied", "Access denied")
	h.clock.Advance(5 * time.Second)
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "invalid_grant", "Invalid device code")
}

func TestDeviceCodeExpiry(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{ExpiresIn: time.Minute})
	code := h.requestCode(t, map[string]any{"client_id": "cli"})
	_, cookies := h.signUp(t, "expiry@example.com")
	expectOK(t, h.Get(t, "/api/auth/device?user_code="+code.UserCode, withCookie(cookies)))

	// Step 1: past the lifetime the user code is expired on every user endpoint
	h.clock.Advance(time.Minute + time.Second)
	expectOAuthError(t, h.Get(t, "/api/auth/device?user_code="+code.UserCode, withCookie(cookies)), 400, "expired_token", "User code has expired")
	expectOAuthError(t, h.Post(t, "/api/auth/device/approve", map[string]any{"userCode": code.UserCode}, withCookie(cookies)),
		400, "expired_token", "User code has expired")
	expectOAuthError(t, h.Post(t, "/api/auth/device/deny", map[string]any{"userCode": code.UserCode}, withCookie(cookies)),
		400, "expired_token", "User code has expired")

	// Step 2: the device gets expired_token once; the row is deleted
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "expired_token", "Device code has expired")
	h.clock.Advance(10 * time.Second)
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "invalid_grant", "Invalid device code")
	expectOAuthError(t, h.Get(t, "/api/auth/device?user_code="+code.UserCode), 400, "invalid_request", "Invalid user code")
}

func TestApprovedButExpiredIsExpired(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{ExpiresIn: time.Minute})
	code := h.requestCode(t, map[string]any{"client_id": "cli"})
	_, cookies := h.signUp(t, "late@example.com")
	h.claimAndApprove(t, cookies, code.UserCode)
	h.clock.Advance(2 * time.Minute)
	expectOAuthError(t, h.poll(t, code.DeviceCode, "cli"), 400, "expired_token", "Device code has expired")
}

// ─── Clients ─────────────────────────────────────────────────────────────────

func TestClientValidation(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{
		ValidateClient: func(_ context.Context, id string) (bool, error) {
			if id == "boom" {
				return false, errors.New("lookup failed")
			}
			return id == "cli" || id == "other", nil
		},
	})

	// Step 1: unknown clients are refused on /device/code (invalid_client) and /device/token (invalid_grant)
	expectOAuthError(t, h.Post(t, "/api/auth/device/code", map[string]any{"client_id": "evil"}), 400, "invalid_client", "Invalid client ID")
	code := h.requestCode(t, map[string]any{"client_id": "cli"})
	expectOAuthError(t, h.poll(t, code.DeviceCode, "evil"), 400, "invalid_grant", "Invalid client ID")

	// Step 2: a known client cannot poll another client's code
	expectOAuthError(t, h.poll(t, code.DeviceCode, "other"), 400, "invalid_grant", "Client ID mismatch")

	// Step 3: an unknown device code
	expectOAuthError(t, h.poll(t, "nope", "cli"), 400, "invalid_grant", "Invalid device code")

	// Step 4: a failing validator is an internal error
	r := h.Post(t, "/api/auth/device/code", map[string]any{"client_id": "boom"})
	if r.Status != http.StatusInternalServerError {
		t.Fatalf("status = %d (%s)", r.Status, r.Body)
	}
}

func TestTokenValidation(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{})
	expectValidation(t, h.Post(t, "/api/auth/device/token", map[string]any{"grant_type": "authorization_code", "device_code": "x", "client_id": "c"}),
		`[body.grant_type] Invalid input: expected "urn:ietf:params:oauth:grant-type:device_code"`)
	expectValidation(t, h.Post(t, "/api/auth/device/token", map[string]any{}),
		`[body.grant_type] Invalid input: expected "urn:ietf:params:oauth:grant-type:device_code"; `+
			`[body.device_code] Invalid input: expected string, received undefined; `+
			`[body.client_id] Invalid input: expected string, received undefined`)
}

func TestFormEncodedRequests(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{})
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

	// Step 1: RFC 8628 clients post forms
	r := h.Post(t, "/api/auth/device/code", []byte("client_id=cli&scope=openid+email"), form)
	expectOK(t, r)
	var code dtos.DeviceCodeResponse
	r.JSON(t, &code)
	rec, _ := h.plugin.Service().FindByUserCode(context.Background(), code.UserCode)
	if rec == nil || *rec.Scope != "openid email" {
		t.Fatalf("row = %+v", rec)
	}
	body := url.Values{"grant_type": {dtos.GrantTypeDeviceCode}, "device_code": {code.DeviceCode}, "client_id": {"cli"}}
	expectOAuthError(t, h.Post(t, "/api/auth/device/token", []byte(body.Encode()), form), 400, "authorization_pending", "")

	// Step 2: validation applies to form bodies too
	expectValidation(t, h.Post(t, "/api/auth/device/code", []byte("scope=x"), form),
		"[body.client_id] Invalid input: expected string, received undefined")
}

// ─── The user's endpoints ────────────────────────────────────────────────────

func TestUserEndpointErrors(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{})
	code := h.requestCode(t, map[string]any{"client_id": "cli"})
	aliceID, alice := h.signUp(t, "alice@example.com")
	_, bob := h.signUp(t, "bob@example.com")

	// Step 1: unknown user codes and a missing query parameter
	expectOAuthError(t, h.Get(t, "/api/auth/device?user_code=NOPE"), 400, "invalid_request", "Invalid user code")
	expectValidation(t, h.Get(t, "/api/auth/device"), "[query.user_code] Invalid input: expected string, received undefined")

	// Step 2: approve / deny need a session (better-auth's own 401 body)
	for _, path := range []string{"/api/auth/device/approve", "/api/auth/device/deny"} {
		expectOAuthError(t, h.Post(t, path, map[string]any{"userCode": code.UserCode}), 401, "unauthorized", "Authentication required")
		expectValidation(t, h.Post(t, path, map[string]any{}, withCookie(alice)), "[body.userCode] Invalid input: expected string, received undefined")
		expectOAuthError(t, h.Post(t, path, map[string]any{"userCode": "NOPE"}, withCookie(alice)), 400, "invalid_request", "Invalid user code")
	}

	// Step 3: a code nobody claimed cannot be decided
	expectOAuthError(t, h.Post(t, "/api/auth/device/approve", map[string]any{"userCode": code.UserCode}, withCookie(alice)),
		400, "invalid_request", services.ErrorCodes["DEVICE_CODE_NOT_CLAIMED"])

	// Step 4: an anonymous visit does not claim it; Alice's visit does, and Bob's later visit doesn't steal it
	expectOK(t, h.Get(t, "/api/auth/device?user_code="+code.UserCode))
	expectOK(t, h.Get(t, "/api/auth/device?user_code="+code.UserCode, withCookie(alice)))
	expectOK(t, h.Get(t, "/api/auth/device?user_code="+code.UserCode, withCookie(bob)))
	rec, _ := h.plugin.Service().FindByUserCode(context.Background(), code.UserCode)
	if rec.UserID == nil || *rec.UserID != aliceID {
		t.Fatalf("claim = %+v", rec.UserID)
	}

	// Step 5: Bob may neither approve nor deny Alice's code
	expectOAuthError(t, h.Post(t, "/api/auth/device/approve", map[string]any{"userCode": code.UserCode}, withCookie(bob)),
		403, "access_denied", "You are not authorized to approve this device authorization")
	expectOAuthError(t, h.Post(t, "/api/auth/device/deny", map[string]any{"userCode": code.UserCode}, withCookie(bob)),
		403, "access_denied", "You are not authorized to deny this device authorization")

	// Step 6: Alice approves once
	expectOK(t, h.Post(t, "/api/auth/device/approve", map[string]any{"userCode": code.UserCode}, withCookie(alice)))
	expectOAuthError(t, h.Post(t, "/api/auth/device/approve", map[string]any{"userCode": code.UserCode}, withCookie(alice)),
		400, "invalid_request", "Device code already processed")
}

func TestConcurrentPollsIssueOneSession(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{})
	code := h.requestCode(t, map[string]any{"client_id": "cli"})
	_, cookies := h.signUp(t, "race@example.com")
	h.claimAndApprove(t, cookies, code.UserCode)

	// Step 1: many polls at once (no previous poll, so none is slowed down)
	var wg sync.WaitGroup
	var ok, failed atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := h.poll(t, code.DeviceCode, "cli"); r.Status == http.StatusOK {
				ok.Add(1)
			} else {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()

	// Step 2: exactly one of them got a session
	if ok.Load() != 1 || failed.Load() != 7 {
		t.Fatalf("ok = %d, failed = %d", ok.Load(), failed.Load())
	}
}

func TestDisabledOps(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{}, func(c *config.AuthConfig) {
		c.DisabledPaths = append(c.DisabledPaths, "/device/deny")
	})
	if r := h.Post(t, "/api/auth/device/deny", map[string]any{"userCode": "x"}); r.Status != http.StatusNotFound && r.Status != http.StatusMethodNotAllowed {
		t.Fatalf("disabled route status = %d", r.Status)
	}
}

func TestRenamedTable(t *testing.T) {
	h := newHarness(t, daconfig.DeviceAuthorizationConfig{
		ModelName:  "device_grants",
		FieldNames: map[string]string{"userCode": "display_code"},
	})
	code := h.requestCode(t, map[string]any{"client_id": "cli"})
	var n int64
	if err := h.DB.Table("device_grants").Where("display_code = ?", code.UserCode).Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("renamed table: n=%d err=%v", n, err)
	}
}

// ─── Unit ────────────────────────────────────────────────────────────────────

func TestDefaultUserCode(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c, err := services.DefaultUserCode(8)
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 8 || strings.Trim(c, daconfig.UserCodeCharset) != "" {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
	if len(seen) < 199 {
		t.Fatalf("codes repeat: %d unique", len(seen))
	}
	if c, _ := services.DefaultUserCode(12); len(c) != 12 {
		t.Fatalf("length 12: %q", c)
	}
}
