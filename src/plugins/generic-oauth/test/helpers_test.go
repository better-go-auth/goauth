package test

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	genericoauth "github.com/better-go-auth/goauth/src/plugins/generic-oauth"
	goconfig "github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const (
	baseURL      = "http://localhost:3000"
	clientID     = "client-id"
	clientSecret = "client-secret"
	// defaultErrorURL is "<baseURL><basePath>/error".
	defaultErrorURL = baseURL + "/api/auth/error"
	// callbackURI is the redirect_uri of the "fake" provider.
	callbackURI = baseURL + "/api/auth/oauth2/callback/fake"
)

// env is one goauth server with the generic-oauth plugin pointed at a fake provider.
type env struct {
	s    *compattest.Server
	fake *socialtest.Provider
	// noRedirect fetches provider URLs without following redirects.
	noRedirect *http.Client
}

// fakeProvider is the "fake" provider config wired to the fake's explicit endpoints (PKCE on).
func fakeProvider(fake *socialtest.Provider) goconfig.ProviderConfig {
	return goconfig.ProviderConfig{
		ProviderID:       "fake",
		AuthorizationURL: fake.AuthorizationEndpoint(),
		TokenURL:         fake.TokenEndpoint(),
		UserInfoURL:      fake.UserInfoEndpoint(),
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		Scopes:           []string{"openid", "email", "profile"},
		PKCE:             true,
	}
}

type envOpts struct {
	// provider mutates the "fake" provider config.
	provider func(fake *socialtest.Provider, pc *goconfig.ProviderConfig)
	// plugin mutates the plugin config (after the "fake" provider was added).
	plugin func(fake *socialtest.Provider, cfg *goconfig.Config)
	core   func(c *config.AuthConfig)
	// extra plugins installed next to generic-oauth.
	extra func(fake *socialtest.Provider, p *genericoauth.Plugin) []compattest.Option
}

// newEnv starts the fake provider and the server.
func newEnv(t *testing.T, opts ...envOpts) *env {
	t.Helper()
	// Step 1: the fake provider
	fake := socialtest.New(clientID, clientSecret)
	t.Cleanup(fake.Close)
	// Step 2: plugin config
	pc := fakeProvider(fake)
	for _, o := range opts {
		if o.provider != nil {
			o.provider(fake, &pc)
		}
	}
	cfg := goconfig.Config{Providers: []goconfig.ProviderConfig{pc}}
	for _, o := range opts {
		if o.plugin != nil {
			o.plugin(fake, &cfg)
		}
	}
	plugin := genericoauth.New(cfg)
	// Step 3: the server (BaseURL drives redirect_uri; the fake redirects to the real test server instead)
	serverOpts := []compattest.Option{compattest.WithPlugin(plugin), compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = baseURL
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		for _, o := range opts {
			if o.core != nil {
				o.core(c)
			}
		}
	})}
	for _, o := range opts {
		if o.extra != nil {
			serverOpts = append(serverOpts, o.extra(fake, plugin)...)
		}
	}
	s := compattest.NewServer(t, serverOpts...)
	fake.SetRedirectBase(s.URL)
	return &env{s: s, fake: fake, noRedirect: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// signIn posts /sign-in/oauth2 (providerId defaults to "fake").
func (e *env) signIn(t *testing.T, body map[string]any) *compattest.Response {
	t.Helper()
	if _, ok := body["providerId"]; !ok {
		body["providerId"] = "fake"
	}
	return e.s.Post(t, "/api/auth/sign-in/oauth2", body)
}

// redirectBody is the {url, redirect} body.
type redirectBody struct {
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
}

// startFlow posts /sign-in/oauth2 and returns the authorization URL.
func (e *env) startFlow(t *testing.T, body map[string]any) string {
	t.Helper()
	res := e.signIn(t, body)
	if res.Status != http.StatusOK {
		t.Fatalf("sign-in/oauth2: %d %s", res.Status, res.Body)
	}
	var out redirectBody
	res.JSON(t, &out)
	if out.URL == "" {
		t.Fatalf("sign-in/oauth2: unexpected body %s", res.Body)
	}
	return out.URL
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

// flow runs sign-in → authorize → callback and returns the callback response.
func (e *env) flow(t *testing.T, body map[string]any) *compattest.Response {
	t.Helper()
	cb := e.authorize(t, e.startFlow(t, body))
	return e.s.Get(t, cb)
}

// linkFlow runs /oauth2/link → authorize → callback with the current session.
func (e *env) linkFlow(t *testing.T, body map[string]any) *compattest.Response {
	t.Helper()
	if _, ok := body["providerId"]; !ok {
		body["providerId"] = "fake"
	}
	if _, ok := body["callbackURL"]; !ok {
		body["callbackURL"] = "/settings"
	}
	r := e.s.Post(t, "/api/auth/oauth2/link", body)
	if r.Status != http.StatusOK {
		t.Fatalf("oauth2/link: %d %s", r.Status, r.Body)
	}
	var out redirectBody
	r.JSON(t, &out)
	if out.URL == "" || !out.Redirect {
		t.Fatalf("oauth2/link: unexpected body %s", r.Body)
	}
	return e.s.Get(t, e.authorize(t, out.URL))
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
	if u.Host == "" {
		base = u.Path
	}
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

// accounts returns the accounts of providerID.
func accounts(t *testing.T, e *env, providerID string) []models.Account {
	t.Helper()
	var out []models.Account
	if err := e.s.DB.Where("provider_id = ?", providerID).Find(&out).Error; err != nil {
		t.Fatal(err)
	}
	return out
}

// userByEmail loads a user (nil when missing).
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

// freshBrowser replaces the cookie jar (a new browser without cookies).
func freshBrowser(e *env) {
	jar, _ := cookiejar.New(nil)
	e.s.Client.Jar = jar
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
