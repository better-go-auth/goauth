package test

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/oidctest"
)

// trusted is a confidential trusted client that skips consent.
var trusted = oidcconfig.Client{
	ClientID: "trusted-app", ClientSecret: "trusted-secret-0123456789abcdef0123456789", Type: oidcconfig.ClientTypeWeb, Name: "Trusted App",
	RedirectURLs: []string{rpCallback, "https://rp.example.com/other"}, SkipConsent: true,
}

// publicClient is a public trusted client (PKCE, no secret).
var publicClient = oidcconfig.Client{
	ClientID: "public-app", Type: oidcconfig.ClientTypePublic, Name: "Public App",
	RedirectURLs: []string{"myapp://callback"}, SkipConsent: true,
}

// disabledClient is a disabled trusted client.
var disabledClient = oidcconfig.Client{
	ClientID: "disabled-app", ClientSecret: "x", Type: oidcconfig.ClientTypeWeb, Name: "Disabled",
	RedirectURLs: []string{rpCallback}, Disabled: true, SkipConsent: true,
}

// codeEnv is an env with the trusted clients and a signed-in browser.
type codeEnv struct {
	*env
	user   *oidctest.Browser
	userID string
}

func newCodeEnv(t *testing.T, cfg oidcconfig.Config) *codeEnv {
	t.Helper()
	cfg.TrustedClients = append(cfg.TrustedClients, trusted, publicClient, disabledClient)
	e := newEnv(t, cfg)
	b := e.srv.Browser()
	id := b.SignUp("user@example.com", "Test User")
	return &codeEnv{env: e, user: b, userID: id}
}

// code runs /oauth2/authorize for the signed-in user and returns the authorization code.
func (c *codeEnv) code(params map[string]string) string {
	c.t.Helper()
	q := map[string]string{"response_type": "code", "client_id": trusted.ClientID, "redirect_uri": rpCallback, "scope": "openid profile email offline_access", "state": "s"}
	for k, v := range params {
		q[k] = v
	}
	r := c.user.Get(c.authorizeURL(q))
	if r.Status != http.StatusFound {
		c.t.Fatalf("authorize: %s", r)
	}
	code, _ := codeFrom(c.t, r.Header.Get("Location"))
	return code
}

// exchange posts an authorization_code grant for the trusted client (client_secret_post).
func (c *codeEnv) exchange(code string, extra url.Values) *oidctest.Response {
	c.t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback},
		"client_id": {trusted.ClientID}, "client_secret": {trusted.ClientSecret}}
	for k, v := range extra {
		form[k] = v
	}
	return c.token(c.srv.Browser(), form)
}

func TestTokenEndpointErrors(t *testing.T) {
	c := newCodeEnv(t, oidcconfig.Config{})
	rp := c.srv.Browser()

	// Step 1: body handling (better-call's media types and record schema)
	r := rp.Post(c.srv.Path("/oauth2/token"), nil)
	if r.Status != http.StatusBadRequest || r.JSON()["code"] != "VALIDATION_ERROR" ||
		r.JSON()["message"] != "[body] Invalid input: expected record, received undefined" {
		t.Fatalf("empty body: %s", r)
	}
	r = rp.Post(c.srv.Path("/oauth2/token"), []byte("x"), map[string]string{"Content-Type": "text/plain"})
	if r.Status != http.StatusUnsupportedMediaType || r.JSON()["code"] != "UNSUPPORTED_MEDIA_TYPE" {
		t.Fatalf("text body: %s", r)
	}
	r = rp.Post(c.srv.Path("/oauth2/token"), []byte("{bad"), map[string]string{"Content-Type": "application/json"})
	if r.Status != http.StatusBadRequest || r.JSON()["message"] != "Invalid JSON in request body" {
		t.Fatalf("bad json: %s", r)
	}

	// Step 2: the authorization_code grant, check by check
	cases := []struct {
		name        string
		form        url.Values
		headers     map[string]string
		status      int
		code, descr string
	}{
		{"missing code", url.Values{"grant_type": {"authorization_code"}}, nil, 400, "invalid_request", "code is required"},
		{"unknown code", url.Values{"grant_type": {"authorization_code"}, "code": {"nope"}}, nil, 401, "invalid_grant", "invalid code"},
		{"missing client_id", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}}, nil, 401, "invalid_client", "client_id is required"},
		{"missing grant_type", url.Values{"code": {"$code"}, "client_id": {trusted.ClientID}}, nil, 400, "invalid_request", "grant_type is required"},
		{"unsupported grant", url.Values{"grant_type": {"password"}, "code": {"$code"}, "client_id": {trusted.ClientID}}, nil, 400, "unsupported_grant_type", "grant_type must be 'authorization_code'"},
		{"missing redirect_uri", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}, "client_id": {trusted.ClientID}}, nil, 400, "invalid_request", "redirect_uri is required"},
		{"unknown client", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}, "client_id": {"ghost"}, "redirect_uri": {rpCallback}}, nil, 401, "invalid_client", "invalid client_id"},
		{"disabled client", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}, "client_id": {disabledClient.ClientID}, "redirect_uri": {rpCallback}}, nil, 401, "invalid_client", "client is disabled"},
		{"code of another client", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}, "client_id": {publicClient.ClientID}, "redirect_uri": {rpCallback}}, nil, 401, "invalid_client", "invalid client_id"},
		{"bad redirect_uri", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}, "client_id": {trusted.ClientID}, "redirect_uri": {"https://rp.example.com/other"}}, nil, 401, "invalid_client", "invalid redirect_uri"},
		{"missing secret", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}, "client_id": {trusted.ClientID}, "redirect_uri": {rpCallback}}, nil, 401, "invalid_client", "client_secret is required for confidential clients"},
		{"wrong secret", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}, "client_id": {trusted.ClientID}, "client_secret": {"wrong"}, "redirect_uri": {rpCallback}}, nil, 401, "invalid_client", "invalid client_secret"},
		{"wrong basic secret", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}, "redirect_uri": {rpCallback}}, basic(trusted.ClientID, "wrong"), 401, "invalid_client", "invalid client_secret"},
		{"malformed basic", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}}, map[string]string{"Authorization": "Basic !!!"}, 401, "invalid_client", "invalid authorization header format"},
		{"basic without colon", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}}, map[string]string{"Authorization": "Basic " + b64("nocolon")}, 401, "invalid_client", "invalid authorization header format"},
		{"basic empty secret", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}}, map[string]string{"Authorization": "Basic " + b64("id:")}, 401, "invalid_client", "invalid authorization header format"},
		{"basic id mismatch", url.Values{"grant_type": {"authorization_code"}, "code": {"$code"}, "client_id": {"other"}}, basic(trusted.ClientID, trusted.ClientSecret), 401, "invalid_client", "client_id in body does not match Authorization header"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			for k, v := range tc.form {
				form[k] = append([]string{}, v...)
			}
			if form.Get("code") == "$code" {
				form.Set("code", c.code(nil))
			}
			r := c.token(rp, form, tc.headers)
			expectOAuthError(t, r, tc.status, tc.code, tc.descr)
		})
	}

	// Step 3: a code is consumed even by a failed exchange (better-auth consumes it first)
	code := c.code(nil)
	expectOAuthError(t, c.exchange(code, url.Values{"client_secret": {"wrong"}}), 401, "invalid_client", "invalid client_secret")
	expectOAuthError(t, c.exchange(code, nil), 401, "invalid_grant", "invalid code")

	// Step 4: an expired code is rejected
	code = c.code(nil)
	expireVerification(t, c.env, code)
	expectOAuthError(t, c.exchange(code, nil), 401, "invalid_grant", "invalid code")

	// Step 5: JSON bodies and client_secret_basic work too
	r = rp.Post(c.srv.Path("/oauth2/token"), map[string]any{"grant_type": "authorization_code", "code": c.code(nil), "redirect_uri": rpCallback},
		basic(trusted.ClientID, trusted.ClientSecret))
	if r.Status != http.StatusOK || r.JSON()["access_token"] == nil {
		t.Fatalf("json body + basic: %s", r)
	}
}

func TestPKCE(t *testing.T) {
	c := newCodeEnv(t, oidcconfig.Config{})
	verifier, challenge := pkce()

	// Step 1: S256 (any case) needs the right verifier
	code := c.code(map[string]string{"code_challenge": challenge, "code_challenge_method": "s256"})
	expectOAuthError(t, c.exchange(code, nil), 400, "invalid_request", "code verifier is missing")
	code = c.code(map[string]string{"code_challenge": challenge, "code_challenge_method": "S256"})
	expectOAuthError(t, c.exchange(code, url.Values{"code_verifier": {"wrong"}}), 401, "invalid_request", "code verification failed")
	code = c.code(map[string]string{"code_challenge": challenge, "code_challenge_method": "S256"})
	if r := c.exchange(code, url.Values{"code_verifier": {verifier}}); r.Status != http.StatusOK {
		t.Fatalf("S256: %s", r)
	}

	// Step 2: plain is refused unless allowed
	r := c.user.Get(c.authorizeURL(map[string]string{"response_type": "code", "client_id": trusted.ClientID, "redirect_uri": rpCallback,
		"code_challenge": "abc", "code_challenge_method": "plain"}))
	expectRedirectError(t, r, rpCallback, "invalid_request", "invalid code_challenge method")
	r = c.user.Get(c.authorizeURL(map[string]string{"response_type": "code", "client_id": trusted.ClientID, "redirect_uri": rpCallback, "code_challenge": "abc"}))
	expectRedirectError(t, r, rpCallback, "invalid_request", "invalid code_challenge method")
	r = c.user.Get(c.authorizeURL(map[string]string{"response_type": "code", "client_id": trusted.ClientID, "redirect_uri": rpCallback, "code_challenge_method": "S256"}))
	expectRedirectError(t, r, rpCallback, "invalid_request", "code_challenge_method requires code_challenge")

	// Step 3: public clients must use PKCE and need no secret
	pub := func(params map[string]string) string {
		q := map[string]string{"client_id": publicClient.ClientID, "redirect_uri": "myapp://callback"}
		for k, v := range params {
			q[k] = v
		}
		return c.code(q)
	}
	code = pub(nil)
	r = c.token(c.srv.Browser(), url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"myapp://callback"}, "client_id": {publicClient.ClientID}})
	expectOAuthError(t, r, 400, "invalid_request", "code verifier is required for public clients")
	code = pub(map[string]string{"code_challenge": challenge, "code_challenge_method": "S256"})
	r = c.token(c.srv.Browser(), url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"myapp://callback"},
		"client_id": {publicClient.ClientID}, "code_verifier": {verifier}})
	// Step 4: better-auth signs an HS256 id_token with the client secret for every exchange, which fails for
	// a client without one (jose: "Zero-length key is not supported"): public clients need UseJWTPlugin
	if r.Status != http.StatusInternalServerError {
		t.Fatalf("public client without jwt plugin: %s", r)
	}

	// Step 5: plain allowed, and a missing method means plain
	p := newCodeEnv(t, oidcconfig.Config{AllowPlainCodeChallengeMethod: true})
	code = p.code(map[string]string{"code_challenge": "plain-verifier-123", "code_challenge_method": "plain"})
	if r := p.exchange(code, url.Values{"code_verifier": {"plain-verifier-123"}}); r.Status != http.StatusOK {
		t.Fatalf("plain: %s", r)
	}
	code = p.code(map[string]string{"code_challenge": "plain-verifier-456"})
	if r := p.exchange(code, url.Values{"code_verifier": {"plain-verifier-456"}}); r.Status != http.StatusOK {
		t.Fatalf("plain by default: %s", r)
	}

	// Step 6: RequirePKCE at authorize and at the token endpoint
	q := newCodeEnv(t, oidcconfig.Config{RequirePKCE: true})
	r = q.user.Get(q.authorizeURL(map[string]string{"response_type": "code", "client_id": trusted.ClientID, "redirect_uri": rpCallback}))
	expectRedirectError(t, r, rpCallback, "invalid_request", "pkce is required")
	expectOAuthError(t, q.exchange("anything", nil), 400, "invalid_request", "code verifier is missing")
}

func TestRefreshTokenGrant(t *testing.T) {
	c := newCodeEnv(t, oidcconfig.Config{AccessTokenExpiresIn: 2 * time.Hour, RefreshTokenExpiresIn: 48 * time.Hour})
	r := c.exchange(c.code(nil), nil)
	tok := r.JSON()
	if r.Status != http.StatusOK || tok["expires_in"] != float64(7200) {
		t.Fatalf("token: %s", r)
	}
	refresh := tok["refresh_token"].(string)
	rp := c.srv.Browser()
	grant := func(form url.Values, h ...map[string]string) *oidctest.Response {
		form.Set("grant_type", "refresh_token")
		return c.token(rp, form, h...)
	}
	// Step 1: errors
	expectOAuthError(t, grant(url.Values{}), 400, "invalid_request", "refresh_token is required")
	expectOAuthError(t, grant(url.Values{"refresh_token": {"nope"}}), 401, "invalid_grant", "invalid refresh token")
	expectOAuthError(t, grant(url.Values{"refresh_token": {refresh}, "client_id": {"other"}}), 401, "invalid_client", "invalid client_id")
	expectOAuthError(t, grant(url.Values{"refresh_token": {refresh}, "client_id": {trusted.ClientID}}), 401, "invalid_client", "client_secret is required for confidential clients")
	expectOAuthError(t, grant(url.Values{"refresh_token": {refresh}}, basic(trusted.ClientID, "bad")), 401, "invalid_client", "invalid client_secret")
	// Step 2: success with basic auth; the old refresh token stays valid (better-auth does not rotate it away)
	r = grant(url.Values{"refresh_token": {refresh}}, basic(trusted.ClientID, trusted.ClientSecret))
	if r.Status != http.StatusOK || r.JSON()["expires_in"] != float64(7200) || r.JSON()["refresh_token"] == refresh {
		t.Fatalf("refresh: %s", r)
	}
	if r := grant(url.Values{"refresh_token": {refresh}}, basic(trusted.ClientID, trusted.ClientSecret)); r.Status != http.StatusOK {
		t.Fatalf("second refresh with the same token: %s", r)
	}
	// Step 3: an expired refresh token
	setTokenTime(t, c.env, "refreshToken", refresh, "refreshTokenExpiresAt", time.Now().Add(-time.Minute))
	expectOAuthError(t, grant(url.Values{"refresh_token": {refresh}}, basic(trusted.ClientID, trusted.ClientSecret)), 401, "invalid_grant", "refresh token expired")
	// Step 4: no offline_access → no refresh token, no openid → no id_token
	r = c.exchange(c.code(map[string]string{"scope": "profile"}), nil)
	if r.Status != http.StatusOK || r.JSON()["refresh_token"] != nil || r.JSON()["id_token"] != nil || r.JSON()["scope"] != "profile" {
		t.Fatalf("profile only: %s", r)
	}
}

func TestConcurrentCodeExchange(t *testing.T) {
	c := newCodeEnv(t, oidcconfig.Config{})
	code := c.code(nil)
	var ok, failed int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := c.exchange(code, nil); r.Status == http.StatusOK {
				atomic.AddInt32(&ok, 1)
			} else if r.JSON()["error"] == "invalid_grant" {
				atomic.AddInt32(&failed, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || failed != 7 {
		t.Fatalf("one exchange must win: ok=%d failed=%d", ok, failed)
	}
}

// expireVerification moves a verification's expiry into the past.
func expireVerification(t *testing.T, e *env, identifier string) {
	t.Helper()
	ver, err := e.srv.Auth.Repositories().FindVerificationValue(context.Background(), identifier)
	if err != nil {
		t.Fatalf("find verification: %v", err)
	}
	ver.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := e.srv.Auth.Repositories().UpsertVerificationValue(context.Background(), ver); err != nil {
		t.Fatalf("expire verification: %v", err)
	}
}

// setTokenTime sets a date field of the oauthAccessToken row found by field=value.
func setTokenTime(t *testing.T, e *env, field, value, dateField string, at time.Time) {
	t.Helper()
	store := e.p.Service().Store()
	if _, err := store.Update(context.Background(), oidcconfig.ModelOAuthAccessToken, []adapter.Where{{Field: field, Value: value}},
		adapter.Record{dateField: at}); err != nil {
		t.Fatalf("update token: %v", err)
	}
}
