package test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/mcp"
	mcpconfig "github.com/better-go-auth/goauth/src/plugins/mcp/config"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/oidctest"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
)

const (
	loginPage = "/login"
	callback  = "http://localhost:6274/oauth/callback"
)

type env struct {
	t   *testing.T
	srv *oidctest.Server
	p   *mcp.Plugin
}

// newEnv starts goauth with the mcp plugin, an MCP resource at /mcp protected with Middleware and the
// discovery helpers mounted at the origin (where MCP clients look for them).
func newEnv(t *testing.T, cfg mcpconfig.Config) *env {
	t.Helper()
	if cfg.LoginPage == "" {
		cfg.LoginPage = loginPage
	}
	p := mcp.New(cfg)
	srv := oidctest.NewServer(t, oidctest.Options{Plugins: []plugins.Plugin{p}})
	// Step 1: the MCP server's own routes
	srv.Mux.Handle("/mcp", p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := mcp.SessionFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"userId": s.UserID, "clientId": s.ClientID, "scopes": s.Scopes}})
	})))
	srv.Mux.Handle("/.well-known/oauth-authorization-server", p.OAuthDiscoveryMetadata())
	srv.Mux.Handle("/.well-known/oauth-protected-resource", p.OAuthProtectedResourceMetadata())
	return &env{t: t, srv: srv, p: p}
}

// registerPublic registers a public MCP client (token_endpoint_auth_method none).
func (e *env) registerPublic() string {
	e.t.Helper()
	r := e.srv.Browser().Post(e.srv.Path("/mcp/register"), map[string]any{
		"redirect_uris": []string{callback}, "client_name": "MCP Inspector", "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"},
	})
	if r.Status != http.StatusCreated {
		e.t.Fatalf("register: %s", r)
	}
	return r.JSON()["client_id"].(string)
}

func (e *env) authorizeURL(q map[string]string) string {
	v := url.Values{}
	for k, x := range q {
		v.Set(k, x)
	}
	return e.srv.Path("/mcp/authorize") + "?" + v.Encode()
}

func (e *env) token(form url.Values, h ...map[string]string) *oidctest.Response {
	e.t.Helper()
	return e.srv.Browser().Post(e.srv.Path("/mcp/token"), form, h...)
}

func codeOf(t *testing.T, location string) (string, string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil || u.Query().Get("error") != "" {
		t.Fatalf("location %q", location)
	}
	return u.Query().Get("code"), u.Query().Get("state")
}

func TestMCPDiscovery(t *testing.T) {
	e := newEnv(t, mcpconfig.Config{Resource: "https://mcp.example.com/mcp",
		OIDCConfig: oidcconfig.Config{Metadata: map[string]any{"scopes_supported": []string{"openid", "mcp:tools"}}}})
	b := e.srv.Browser()
	base := e.srv.Path("")
	// Step 1: RFC 8414 metadata under the auth base path and at the origin (helper, with CORS)
	for _, u := range []string{e.srv.Path("/.well-known/oauth-authorization-server"), "/.well-known/oauth-authorization-server"} {
		r := b.Get(u)
		m := r.JSON()
		if r.Status != 200 || m["issuer"] != e.srv.URL || m["authorization_endpoint"] != base+"/mcp/authorize" || m["token_endpoint"] != base+"/mcp/token" ||
			m["registration_endpoint"] != base+"/mcp/register" || m["jwks_uri"] != base+"/mcp/jwks" || m["userinfo_endpoint"] != base+"/mcp/userinfo" {
			t.Fatalf("%s: %s", u, r)
		}
		if u[0] == '/' && (r.Header.Get("Access-Control-Allow-Origin") != "*" || r.Header.Get("Access-Control-Max-Age") != "86400") {
			t.Fatalf("helper CORS headers: %v", r.Header)
		}
	}
	// Step 2: RFC 9728 protected resource metadata
	r := b.Get("/.well-known/oauth-protected-resource")
	m := r.JSON()
	if m["resource"] != "https://mcp.example.com/mcp" || m["authorization_servers"].([]any)[0] != e.srv.URL || m["jwks_uri"] != base+"/mcp/jwks" ||
		len(m["scopes_supported"].([]any)) != 2 || m["bearer_methods_supported"].([]any)[0] != "header" {
		t.Fatalf("protected resource: %s", r)
	}
	r = b.Get(e.srv.Path("/.well-known/oauth-protected-resource"))
	if r.JSON()["resource"] != "https://mcp.example.com/mcp" {
		t.Fatalf("endpoint protected resource: %s", r)
	}
	// Step 3: the default resource is the origin
	d := newEnv(t, mcpconfig.Config{})
	if r := d.srv.Browser().Get("/.well-known/oauth-protected-resource"); r.JSON()["resource"] != d.srv.URL {
		t.Fatalf("default resource: %s", r)
	}
}

// TestMCPFlow is what an MCP client does: 401 with the resource metadata → discovery → registration →
// authorization (login, resume) → token with PKCE → MCP call → refresh.
func TestMCPFlow(t *testing.T) {
	e := newEnv(t, mcpconfig.Config{})
	client := e.srv.Browser()

	// Step 1: the MCP server answers 401 with the JSON-RPC error and WWW-Authenticate
	r := client.Post("/mcp", map[string]any{"jsonrpc": "2.0", "method": "tools/list", "id": 1})
	www := `Bearer resource_metadata="` + e.srv.Path("/.well-known/oauth-protected-resource") + `"`
	if r.Status != 401 || r.Header.Get("WWW-Authenticate") != www || r.Header.Get("Access-Control-Expose-Headers") != "WWW-Authenticate" {
		t.Fatalf("401: %s", r)
	}
	var body struct {
		JSONRPC string `json:"jsonrpc"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			WWW     string `json:"www-authenticate"`
		} `json:"error"`
		ID any `json:"id"`
	}
	if err := json.Unmarshal(r.Body, &body); err != nil || body.JSONRPC != "2.0" || body.Error.Code != -32000 ||
		body.Error.Message != "Unauthorized: Authentication required" || body.Error.WWW != www || body.ID != nil || !strings.Contains(string(r.Body), `"id":null`) {
		t.Fatalf("401 body: %s", r.Body)
	}
	if r := client.Post("/mcp", nil, map[string]string{"Authorization": "Bearer nope"}); r.Status != 401 {
		t.Fatalf("unknown token: %s", r)
	}

	// Step 2: registration of a public client (no secret), CORS headers
	r = e.srv.Browser().Post(e.srv.Path("/mcp/register"), map[string]any{"redirect_uris": []string{callback}, "client_name": "Inspector", "token_endpoint_auth_method": "none"})
	m := r.JSON()
	if r.Status != 201 || m["client_secret"] != nil || m["client_secret_expires_at"] != nil || m["token_endpoint_auth_method"] != "none" ||
		r.Header.Get("Access-Control-Allow-Origin") != "*" || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("register public: %s", r)
	}
	clientID := m["client_id"].(string)
	rec, _ := e.p.Service().Provider.Store().FindOne(context.Background(), oidcconfig.ModelOAuthApplication, []adapter.Where{{Field: "clientId", Value: clientID}})
	if rec["type"] != "public" || rec["clientSecret"] != "" {
		t.Fatalf("stored public client: %v", rec)
	}

	// Step 3: the user authorizes: login page, sign-in resumes /mcp/authorize, code to the client
	user := e.srv.Browser()
	userID := user.SignUp("mcp@example.com", "Mcp User")
	user = e.srv.Browser()
	verifier := services.RandomString(50, services.AlphaLower)
	r = user.Get(e.authorizeURL(map[string]string{"response_type": "code", "client_id": clientID, "redirect_uri": callback, "state": "abc",
		"code_challenge": services.S256(verifier), "code_challenge_method": "S256", "scope": "openid profile email offline_access"}))
	if r.Status != http.StatusFound || !strings.HasPrefix(r.Header.Get("Location"), loginPage+"?") || r.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("authorize: %s", r)
	}
	r = user.SignIn("mcp@example.com")
	code, state := codeOf(t, r.Header.Get("Location"))
	if r.Status != http.StatusFound || state != "abc" || !strings.HasPrefix(r.Header.Get("Location"), callback) {
		t.Fatalf("resume: %s", r)
	}

	// Step 4: token with PKCE only (public client)
	r = e.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "client_id": {clientID}, "code_verifier": {verifier}})
	tok := r.JSON()
	if r.Status != 200 || tok["token_type"] != "Bearer" || tok["refresh_token"] == nil || tok["id_token"] == nil || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("token: %s", r)
	}
	access := tok["access_token"].(string)

	// Step 5: /mcp/get-session and the protected MCP route
	r = e.srv.Browser().Get(e.srv.Path("/mcp/get-session"), map[string]string{"Authorization": "Bearer " + access})
	s := r.JSON()
	if r.Status != 200 || s["userId"] != userID || s["clientId"] != clientID || s["accessToken"] != access || s["scopes"] != "openid profile email offline_access" {
		t.Fatalf("get-session: %s", r)
	}
	if exp, _ := s["accessTokenExpiresAt"].(string); !strings.HasSuffix(exp, "Z") || len(exp) != len("2006-01-02T15:04:05.000Z") {
		t.Fatalf("date format: %v", s["accessTokenExpiresAt"])
	}
	for _, h := range []map[string]string{nil, {"Authorization": "Bearer nope"}} {
		if r := e.srv.Browser().Get(e.srv.Path("/mcp/get-session"), h); r.Status != 200 || strings.TrimSpace(string(r.Body)) != "null" {
			t.Fatalf("get-session without token: %s", r)
		}
	}
	r = client.Post("/mcp", map[string]any{"jsonrpc": "2.0"}, map[string]string{"Authorization": "Bearer " + access})
	if r.Status != 200 || r.JSON()["result"].(map[string]any)["userId"] != userID {
		t.Fatalf("mcp call: %s", r)
	}

	// Step 6: refresh (public client: no secret) answers token_type "bearer"
	r = e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {clientID}})
	if r.Status != 200 || r.JSON()["token_type"] != "bearer" || r.JSON()["access_token"] == access {
		t.Fatalf("refresh: %s", r)
	}
	// Step 7: an expired access token is rejected by the Go helper (goauth checks the expiry)
	if _, err := e.p.Service().Provider.Store().Update(context.Background(), oidcconfig.ModelOAuthAccessToken,
		[]adapter.Where{{Field: "accessToken", Value: access}}, adapter.Record{"accessTokenExpiresAt": time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if r := client.Post("/mcp", nil, map[string]string{"Authorization": "Bearer " + access}); r.Status != 401 {
		t.Fatalf("expired token accepted: %s", r)
	}
}

func TestMCPConfidentialClientAndErrors(t *testing.T) {
	e := newEnv(t, mcpconfig.Config{OIDCConfig: oidcconfig.Config{RequirePKCE: true, AccessTokenExpiresIn: 10 * time.Minute}})
	// Step 1: a confidential client (default client_secret_basic)
	r := e.srv.Browser().Post(e.srv.Path("/mcp/register"), map[string]any{"redirect_uris": []string{callback}, "client_name": "Conf"})
	if r.Status != 201 || r.JSON()["client_secret"] == nil || r.JSON()["client_secret_expires_at"] != float64(0) {
		t.Fatalf("register confidential: %s", r)
	}
	id, secret := r.JSON()["client_id"].(string), r.JSON()["client_secret"].(string)
	user := e.srv.Browser()
	user.SignUp("conf@example.com", "Conf User")
	base := map[string]string{"response_type": "code", "client_id": id, "redirect_uri": callback}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == "" {
				delete(m, kv[i])
			} else {
				m[kv[i]] = kv[i+1]
			}
		}
		return m
	}
	errorBase := e.srv.Path("/error")
	expect := func(r *oidctest.Response, location string) {
		t.Helper()
		if r.Status != http.StatusFound || r.Header.Get("Location") != location {
			t.Fatalf("want %s, got %s", location, r)
		}
	}
	// Step 2: /mcp/authorize errors (better-auth's mcp variants)
	expect(user.Get(e.authorizeURL(with("client_id", ""))), errorBase+"?error=invalid_client")
	expect(user.Get(e.authorizeURL(with("response_type", ""))), errorBase+"?error=invalid_request&error_description=response_type is required")
	expect(user.Get(e.authorizeURL(with("client_id", "ghost"))), errorBase+"?error=invalid_client")
	expect(user.Get(e.authorizeURL(with("response_type", "token"))), errorBase+"?error=unsupported_response_type")
	if r := user.Get(e.authorizeURL(with("redirect_uri", "http://evil.example.com"))); r.Status != 400 || r.JSON()["message"] != "Invalid redirect URI" {
		t.Fatalf("bad redirect: %s", r)
	}
	expect(user.Get(e.authorizeURL(with("scope", "openid nope"))), callback+"?error=invalid_scope&error_description=The following scopes are invalid: nope")
	expect(user.Get(e.authorizeURL(with())), callback+"?error=invalid_request&error_description=pkce is required")
	expect(user.Get(e.authorizeURL(with("code_challenge", "x", "code_challenge_method", "plain"))), callback+"?error=invalid_request&error_description=invalid code_challenge method")
	// Step 3: a code, then token errors: client checks come before the code is matched
	verifier := services.RandomString(48, services.AlphaLower)
	codeFor := func() string {
		r := user.Get(e.authorizeURL(with("code_challenge", services.S256(verifier), "code_challenge_method", "S256", "scope", "openid")))
		c, st := codeOf(t, r.Header.Get("Location"))
		if st != "" {
			t.Fatalf("mcp sets no state when there is none: %q", st)
		}
		return c
	}
	form := func(code string, kv ...string) url.Values {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "client_id": {id}, "code_verifier": {verifier}}
		for i := 0; i+1 < len(kv); i += 2 {
			f.Set(kv[i], kv[i+1])
		}
		return f
	}
	cases := []struct {
		form        url.Values
		h           map[string]string
		status      int
		code, descr string
	}{
		{form("x", "code_verifier", ""), nil, 400, "invalid_request", "code verifier is missing"},
		{form("bad"), nil, 401, "invalid_grant", "invalid code"},
		{form("$"), nil, 401, "invalid_client", "client_secret is required for confidential clients"},
		{form("$", "client_secret", "wrong"), nil, 401, "invalid_client", "invalid client_secret"},
		{form("$", "redirect_uri", "http://other"), map[string]string{"Authorization": basicAuth(id, secret)}, 401, "invalid_client", "invalid redirect_uri"},
		{form("$", "code_verifier", "wrong-verifier"), map[string]string{"Authorization": basicAuth(id, secret)}, 401, "invalid_request", "code verification failed"},
	}
	for i, tc := range cases {
		if tc.form.Get("code") == "$" {
			tc.form.Set("code", codeFor())
		}
		r := e.token(tc.form, tc.h)
		m := r.JSON()
		if r.Status != tc.status || m["error"] != tc.code || m["error_description"] != tc.descr {
			t.Fatalf("case %d: %s", i, r)
		}
	}
	// Step 4: success with basic auth; expires_in follows the OIDC config; id_token present
	r = e.token(form(codeFor()), map[string]string{"Authorization": basicAuth(id, secret)})
	if r.Status != 200 || r.JSON()["expires_in"] != float64(600) || r.JSON()["refresh_token"] != nil || r.JSON()["id_token"] == nil {
		t.Fatalf("token: %s", r)
	}
	// Step 5: registration validation is shared with the oidc-provider
	r = e.srv.Browser().Post(e.srv.Path("/mcp/register"), map[string]any{"redirect_uris": []string{"javascript:alert(1)"}})
	if r.Status != 400 || r.JSON()["code"] != "VALIDATION_ERROR" {
		t.Fatalf("validation: %s", r)
	}
	r = e.srv.Browser().Post(e.srv.Path("/mcp/register"), map[string]any{"redirect_uris": []string{}})
	if r.Status != 400 || r.JSON()["error"] != "invalid_redirect_uri" || r.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("empty redirect uris: %s", r)
	}
}

func TestMCPConsent(t *testing.T) {
	e := newEnv(t, mcpconfig.Config{OIDCConfig: oidcconfig.Config{ConsentPage: "/consent"}})
	id := e.registerPublic()
	user := e.srv.Browser()
	user.SignUp("consent@example.com", "Con")
	verifier := services.RandomString(48, services.AlphaLower)
	q := map[string]string{"response_type": "code", "client_id": id, "redirect_uri": callback, "state": "st",
		"code_challenge": services.S256(verifier), "code_challenge_method": "S256"}
	// Step 1: without prompt=consent the mcp plugin skips consent
	r := user.Get(e.authorizeURL(q))
	if !strings.HasPrefix(r.Header.Get("Location"), callback+"?code=") {
		t.Fatalf("no consent: %s", r)
	}
	// Step 2: prompt=consent goes to the consent page; /oauth2/consent issues the code with the state
	q["prompt"] = "consent"
	r = user.Get(e.authorizeURL(q))
	loc := r.Location()
	if loc == nil || loc.Path != "/consent" || r.Cookie(services.ConsentPromptCookie) == nil {
		t.Fatalf("consent page: %s", r)
	}
	r = user.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true})
	code, state := codeOf(t, r.JSON()["redirectURI"].(string))
	if state != "st" {
		t.Fatalf("consent redirect: %s", r)
	}
	r = e.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "client_id": {id}, "code_verifier": {verifier}})
	if r.Status != 200 {
		t.Fatalf("token after consent: %s", r)
	}
}

func basicAuth(id, secret string) string {
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	req.SetBasicAuth(id, secret)
	return req.Header.Get("Authorization")
}
