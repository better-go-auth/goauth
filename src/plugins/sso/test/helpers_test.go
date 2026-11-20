package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	"github.com/better-go-auth/goauth/src/plugins/sso"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
	"github.com/better-go-auth/goauth/src/plugins/sso/services"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	baseURL      = "http://localhost:3000"
	authBase     = baseURL + "/api/auth"
	clientID     = "sso-client"
	clientSecret = "sso-secret"
	// defaultErrorURL is "<baseURL><basePath>/error".
	defaultErrorURL = authBase + "/error"
)

// env is one goauth server with the sso plugin and a fake OIDC identity provider.
type env struct {
	s    *compattest.Server
	fake *socialtest.Provider
	sso  *sso.Plugin
	org  *org.OrgPlugin
	// noRedirect fetches IdP URLs without following redirects.
	noRedirect *http.Client
}

type envOpts struct {
	// sso mutates the plugin config.
	sso func(fake *socialtest.Provider, c *ssoconfig.SSOConfig)
	// core mutates the auth config.
	core func(c *config.AuthConfig)
	// withOrg installs the organization plugin.
	withOrg bool
}

// newEnv starts the fake IdP and the server (the fake's origin is trusted: it runs on 127.0.0.1).
func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	// Step 1: the fake identity provider
	fake := socialtest.New(clientID, clientSecret)
	t.Cleanup(fake.Close)
	// Step 2: the sso plugin (and the organization plugin on a database we open)
	cfg := ssoconfig.SSOConfig{}
	if o.sso != nil {
		o.sso(fake, &cfg)
	}
	e := &env{fake: fake, sso: sso.New(cfg), noRedirect: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	opts := []compattest.Option{compattest.WithPlugin(e.sso), compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = baseURL
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		if o.core != nil {
			o.core(c)
		}
	})}
	if o.withOrg {
		db := openDB(t)
		op, err := org.NewWithGorm(db, orgconfig.OrgConfig{})
		if err != nil {
			t.Fatal(err)
		}
		e.org = op
		opts = append(opts, compattest.WithDB(db), compattest.WithPlugin(op))
	}
	// Step 3: the server; the fake IdP redirects back to the real test server
	e.s = compattest.NewServer(t, opts...)
	fake.SetRedirectBase(e.s.URL)
	return e
}

// openDB opens a private in-memory sqlite database (one connection, like compattest).
func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:sso_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	return db
}

// signUp creates a verified-or-not email user and leaves its session in the jar.
func (e *env) signUp(t *testing.T, email string) string {
	t.Helper()
	r := e.s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": "password1234", "name": "Admin User"})
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

// freshBrowser replaces the cookie jar (a browser without cookies).
func (e *env) freshBrowser() {
	jar, _ := cookiejar.New(nil)
	e.s.Client.Jar = jar
}

// oidcProvider is a registration body for the fake IdP (discovery on).
func (e *env) oidcProvider(providerID, domain string) map[string]any {
	return map[string]any{
		"providerId": providerID,
		"issuer":     e.fake.Issuer,
		"domain":     domain,
		"oidcConfig": map[string]any{"clientId": clientID, "clientSecret": clientSecret},
	}
}

// register posts /sso/register with the session in the jar.
func (e *env) register(t *testing.T, body map[string]any) *compattest.Response {
	t.Helper()
	return e.s.Post(t, "/api/auth/sso/register", body)
}

// mustRegister registers and fails the test on errors.
func (e *env) mustRegister(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	r := e.register(t, body)
	if r.Status != http.StatusOK {
		t.Fatalf("register: %d %s", r.Status, r.Body)
	}
	var out map[string]any
	r.JSON(t, &out)
	return out
}

// redirectBody is the {url, redirect} body.
type redirectBody struct {
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
}

// startSignIn posts /sign-in/sso and returns the IdP URL.
func (e *env) startSignIn(t *testing.T, body map[string]any) string {
	t.Helper()
	r := e.s.Post(t, "/api/auth/sign-in/sso", body)
	if r.Status != http.StatusOK {
		t.Fatalf("sign-in/sso: %d %s", r.Status, r.Body)
	}
	var out redirectBody
	r.JSON(t, &out)
	if out.URL == "" || !out.Redirect {
		t.Fatalf("sign-in/sso: unexpected body %s", r.Body)
	}
	return out.URL
}

// authorize follows the authorization URL at the fake IdP and returns the callback path on the test server.
func (e *env) authorize(t *testing.T, authURL string) string {
	t.Helper()
	resp, err := e.noRedirect.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, e.s.URL) {
		t.Fatalf("authorize: unexpected redirect %s", loc)
	}
	return strings.TrimPrefix(loc, e.s.URL)
}

// oidcFlow runs sign-in → IdP authorize → callback and returns the callback response.
func (e *env) oidcFlow(t *testing.T, body map[string]any) *compattest.Response {
	t.Helper()
	return e.s.Get(t, e.authorize(t, e.startSignIn(t, body)))
}

// location returns the Location of a 302.
func location(t *testing.T, r *compattest.Response) string {
	t.Helper()
	if r.Status != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", r.Status, r.Body)
	}
	return r.Header.Get("Location")
}

// errorParams returns the error / error_description of a redirect to base.
func errorParams(t *testing.T, r *compattest.Response, base string) url.Values {
	t.Helper()
	loc := location(t, r)
	if !strings.HasPrefix(loc, base+"?") {
		t.Fatalf("expected redirect to %s?..., got %s", base, loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad location %q", loc)
	}
	return u.Query()
}

// sessionCookie returns the session_token Set-Cookie, or nil.
func sessionCookie(r *compattest.Response) *http.Cookie {
	return r.Cookie("better-auth.session_token")
}

// errBody decodes {"code", "message"}.
func errBody(t *testing.T, r *compattest.Response) (string, string) {
	t.Helper()
	var out struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	r.JSON(t, &out)
	return out.Code, out.Message
}

// expectError asserts a JSON error.
func expectError(t *testing.T, r *compattest.Response, status int, code, message string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("expected %d, got %d: %s", status, r.Status, r.Body)
	}
	c, m := errBody(t, r)
	if c != code || (message != "" && m != message) {
		t.Fatalf("expected %s %q, got %s %q", code, message, c, m)
	}
}

// userByEmail loads a user through the repositories (nil when missing).
func (e *env) userByEmail(t *testing.T, email string) *models.User {
	t.Helper()
	u, err := e.s.Auth.Repositories().FindUserByEmail(context.Background(), email)
	if err != nil {
		return nil
	}
	return u
}

// accountsOf lists the accounts of userID.
func (e *env) accountsOf(t *testing.T, userID string) []models.Account {
	t.Helper()
	out, err := e.s.Auth.Repositories().FindAccounts(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// providerRow loads the stored ssoProvider record.
func (e *env) providerRow(t *testing.T, providerID string) adapter.Record {
	t.Helper()
	r, err := e.s.Auth.Adapter().FindOne(context.Background(), services.Model, []adapter.Where{{Field: "providerId", Value: providerID}})
	if err != nil {
		return nil
	}
	return r
}

// jsonOf decodes a stored JSON column.
func jsonOf(t *testing.T, v any) map[string]any {
	t.Helper()
	s, _ := v.(string)
	var out map[string]any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return out
}
