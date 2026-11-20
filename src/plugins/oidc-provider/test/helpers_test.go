package test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	oidcprovider "github.com/better-go-auth/goauth/src/plugins/oidc-provider"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/oidctest"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
)

const (
	loginPage   = "/login"
	consentPage = "/consent"
	rpCallback  = "https://rp.example.com/callback"
)

// env is an oidc-provider test server.
type env struct {
	t   *testing.T
	srv *oidctest.Server
	p   *oidcprovider.Plugin
}

// newEnv starts goauth with the oidc-provider (LoginPage /login, ConsentPage /consent unless set) and the
// extra plugins.
func newEnv(t *testing.T, cfg oidcconfig.Config, extra ...plugins.Plugin) *env {
	t.Helper()
	return newEnvWith(t, cfg, nil, extra...)
}

func newEnvWith(t *testing.T, cfg oidcconfig.Config, configure func(*config.AuthConfig), extra ...plugins.Plugin) *env {
	t.Helper()
	if cfg.LoginPage == "" {
		cfg.LoginPage = loginPage
	}
	p := oidcprovider.New(cfg)
	srv := oidctest.NewServer(t, oidctest.Options{Plugins: append(extra, p), Configure: configure})
	return &env{t: t, srv: srv, p: p}
}

// client is a registered OAuth client.
type client struct {
	ID, Secret string
}

// register registers a confidential client through /oauth2/register with the browser's session.
func (e *env) register(b *oidctest.Browser, redirects ...string) client {
	e.t.Helper()
	if len(redirects) == 0 {
		redirects = []string{rpCallback}
	}
	r := b.Post("/api/auth/oauth2/register", map[string]any{"redirect_uris": redirects, "client_name": "RP App"})
	if r.Status != http.StatusCreated {
		e.t.Fatalf("register: %s", r)
	}
	m := r.JSON()
	return client{ID: m["client_id"].(string), Secret: m["client_secret"].(string)}
}

// authorizeURL builds an /oauth2/authorize URL.
func (e *env) authorizeURL(params map[string]string) string {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	return e.srv.Path("/oauth2/authorize") + "?" + q.Encode()
}

// pkce returns a verifier and its S256 challenge.
func pkce() (verifier, challenge string) {
	verifier = services.RandomString(64, services.AlphaLower+services.Digits)
	return verifier, services.S256(verifier)
}

// codeFrom extracts code and state from a redirect to the client.
func codeFrom(t *testing.T, location string) (code, state string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("bad location %q", location)
	}
	if e := u.Query().Get("error"); e != "" {
		t.Fatalf("authorization error %s: %s", e, location)
	}
	return u.Query().Get("code"), u.Query().Get("state")
}

// token posts to /oauth2/token as a form.
func (e *env) token(b *oidctest.Browser, form url.Values, headers ...map[string]string) *oidctest.Response {
	e.t.Helper()
	return b.Post(e.srv.Path("/oauth2/token"), form, headers...)
}

// expectOAuthError checks an RFC 6749 error body.
func expectOAuthError(t *testing.T, r *oidctest.Response, status int, code, description string) {
	t.Helper()
	m := r.JSON()
	if r.Status != status || m["error"] != code || (description != "" && m["error_description"] != description) {
		t.Fatalf("want %d %s %q, got %s", status, code, description, r)
	}
}

// expectRedirectError checks a redirect carrying error / error_description.
func expectRedirectError(t *testing.T, r *oidctest.Response, prefix, code, description string) {
	t.Helper()
	loc := r.Header.Get("Location")
	if r.Status != http.StatusFound || !strings.HasPrefix(loc, prefix) {
		t.Fatalf("want redirect to %s, got %s", prefix, r)
	}
	want := "error=" + code + "&error_description=" + description
	if !strings.Contains(loc, want) {
		t.Fatalf("location %q lacks %q", loc, want)
	}
}

// basic returns an Authorization: Basic header.
func basic(id, secret string) map[string]string {
	return map[string]string{"Authorization": "Basic " + b64(url.QueryEscape(id)+":"+url.QueryEscape(secret))}
}
