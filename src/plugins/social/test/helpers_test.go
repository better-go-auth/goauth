package test

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const (
	baseURL      = "http://localhost:3000"
	clientID     = "client-id"
	clientSecret = "client-secret"
	// defaultErrorURL is "<baseURL><basePath>/error".
	defaultErrorURL = baseURL + "/api/auth/error"
)

// env is one goauth server with the social plugin pointed at a fake provider.
type env struct {
	s    *compattest.Server
	fake *socialtest.Provider
	// noRedirect fetches provider URLs without following redirects.
	noRedirect *http.Client
}

// genericFake is the generic provider "fake" wired to the fake's endpoints.
func genericFake(fake *socialtest.Provider, mut ...func(*providers.GenericOptions)) providers.Provider {
	o := providers.GenericOptions{
		ProviderID: "fake",
		Issuer:     fake.Issuer,
		ProviderOptions: providers.ProviderOptions{
			ClientID:              clientID,
			ClientSecret:          clientSecret,
			AuthorizationEndpoint: fake.AuthorizationEndpoint(),
			TokenEndpoint:         fake.TokenEndpoint(),
			UserInfoEndpoint:      fake.UserInfoEndpoint(),
			JWKSEndpoint:          fake.JWKSEndpoint(),
		},
	}
	for _, m := range mut {
		m(&o)
	}
	return providers.Generic(o)
}

type envOpts struct {
	social func(fake *socialtest.Provider, cfg *socialconfig.SocialConfig)
	core   func(c *config.AuthConfig)
}

// newEnv starts the fake provider and the server. By default the config has the "fake" generic provider.
func newEnv(t *testing.T, opts ...envOpts) *env {
	t.Helper()
	// Step 1: the fake provider
	fake := socialtest.New(clientID, clientSecret)
	t.Cleanup(fake.Close)
	// Step 2: plugin config
	cfg := socialconfig.SocialConfig{Providers: []providers.Provider{genericFake(fake)}}
	for _, o := range opts {
		if o.social != nil {
			o.social(fake, &cfg)
		}
	}
	// Step 3: the server (BaseURL drives redirect_uri; the fake redirects to the real test server instead)
	s := compattest.NewServer(t, compattest.WithPlugin(social.New(cfg)), compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = baseURL
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		for _, o := range opts {
			if o.core != nil {
				o.core(c)
			}
		}
	}))
	fake.SetRedirectBase(s.URL)
	return &env{s: s, fake: fake, noRedirect: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// signIn posts /sign-in/social.
func (e *env) signIn(t *testing.T, body map[string]any) *compattest.Response {
	t.Helper()
	if _, ok := body["provider"]; !ok {
		body["provider"] = "fake"
	}
	return e.s.Post(t, "/api/auth/sign-in/social", body)
}

// authorize follows the authorization URL at the fake and returns the callback path (+query) on the test server.
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

// startFlow posts /sign-in/social with disableRedirect and returns the authorization URL.
func (e *env) startFlow(t *testing.T, body map[string]any) string {
	t.Helper()
	body["disableRedirect"] = true
	res := e.signIn(t, body)
	if res.Status != http.StatusOK {
		t.Fatalf("sign-in/social: %d %s", res.Status, res.Body)
	}
	var out struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	res.JSON(t, &out)
	if out.URL == "" || out.Redirect {
		t.Fatalf("sign-in/social: unexpected body %s", res.Body)
	}
	return out.URL
}

// flow runs sign-in → authorize → callback and returns the callback response.
func (e *env) flow(t *testing.T, body map[string]any) *compattest.Response {
	t.Helper()
	cb := e.authorize(t, e.startFlow(t, body))
	return e.s.Get(t, cb)
}

// location returns the Location header of a 302.
func location(t *testing.T, r *compattest.Response) string {
	t.Helper()
	if r.Status != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", r.Status, r.Body)
	}
	return r.Header.Get("Location")
}

// expectErrorRedirect asserts a redirect to errorURL with ?error=code.
func expectErrorRedirect(t *testing.T, r *compattest.Response, errorURL, code string) url.Values {
	t.Helper()
	loc := location(t, r)
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad location %q", loc)
	}
	base := u.Scheme + "://" + u.Host + u.Path
	if base != strings.Split(errorURL, "?")[0] {
		t.Fatalf("expected redirect to %s, got %s", errorURL, loc)
	}
	if got := u.Query().Get("error"); got != code {
		t.Fatalf("expected error=%s, got %s (%s)", code, got, loc)
	}
	return u.Query()
}

// sessionCookie returns the session_token Set-Cookie, or nil.
func sessionCookie(r *compattest.Response) *http.Cookie {
	return r.Cookie("better-auth.session_token")
}

// accounts returns the user's accounts for providerID.
func accounts(t *testing.T, e *env, providerID string) []models.Account {
	t.Helper()
	var out []models.Account
	if err := e.s.DB.Where("provider_id = ?", providerID).Find(&out).Error; err != nil {
		t.Fatal(err)
	}
	return out
}

// userByEmail loads a user.
func userByEmail(t *testing.T, e *env, email string) *models.User {
	t.Helper()
	var u models.User
	if err := e.s.DB.Where("email = ?", email).Take(&u).Error; err != nil {
		return nil
	}
	return &u
}

// createUser inserts a user directly.
func createUser(t *testing.T, e *env, email string, verified bool) *models.User {
	t.Helper()
	u := &models.User{UserDto: models.UserDto{Name: "Local User", Email: email, EmailVerified: verified}}
	if err := e.s.DB.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

// signUpEmail signs a user up with email/password, leaving the session in the jar.
func signUpEmail(t *testing.T, e *env, email string) {
	t.Helper()
	r := e.s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": "password1234", "name": "Pass Word"})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up: %d %s", r.Status, r.Body)
	}
}

// getSession returns the current session's user email ("" when signed out).
func getSession(t *testing.T, e *env) string {
	t.Helper()
	r := e.s.Get(t, "/api/auth/get-session")
	var out struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if string(r.Body) == "null" {
		return ""
	}
	r.JSON(t, &out)
	return out.User.Email
}

// errCode decodes {"code": ...}.
func errCode(t *testing.T, r *compattest.Response) string {
	t.Helper()
	var out struct {
		Code string `json:"code"`
	}
	r.JSON(t, &out)
	return out.Code
}

// newJar returns an empty cookie jar (a fresh browser).
func newJar() (http.CookieJar, error) { return cookiejar.New(nil) }
