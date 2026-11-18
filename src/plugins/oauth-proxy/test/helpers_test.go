package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	oauthproxy "github.com/better-go-auth/goauth/src/plugins/oauth-proxy"
	proxyconfig "github.com/better-go-auth/goauth/src/plugins/oauth-proxy/config"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	secret       = "oauth-proxy-test-secret-0123456789abcdef"
	clientID     = "client-id"
	clientSecret = "client-secret"
)

// deployment is one goauth server (production or preview) on its own origin, with the social and
// oauth-proxy plugins.
type deployment struct {
	URL   string
	Auth  *goauth.GoAuth
	DB    *gorm.DB
	Proxy *oauthproxy.Plugin
}

// deployOpts customises a deployment.
type deployOpts struct {
	// host is "127.0.0.1" (production) or "localhost" (preview), so the two origins keep separate cookies.
	host     string
	strategy socialconfig.StateStrategy
	proxy    proxyconfig.OAuthProxyConfig
	provider func(*providers.GenericOptions)
	core     func(*config.AuthConfig)
}

// genericFake is the generic provider "fake" wired to the fake provider.
func genericFake(fake *socialtest.Provider, mut func(*providers.GenericOptions)) providers.Provider {
	o := providers.GenericOptions{
		ProviderID: "fake",
		Issuer:     fake.Issuer,
		ProviderOptions: providers.ProviderOptions{
			ClientID: clientID, ClientSecret: clientSecret,
			AuthorizationEndpoint: fake.AuthorizationEndpoint(), TokenEndpoint: fake.TokenEndpoint(),
			UserInfoEndpoint: fake.UserInfoEndpoint(), JWKSEndpoint: fake.JWKSEndpoint(),
		},
	}
	if mut != nil {
		mut(&o)
	}
	return providers.Generic(o)
}

// deploy starts a deployment whose BaseURL is its own address.
func deploy(t *testing.T, fake *socialtest.Provider, o deployOpts) *deployment {
	t.Helper()
	// Step 1: reserve the address so BaseURL is known before setup
	ts := httptest.NewUnstartedServer(nil)
	port := ts.Listener.Addr().(*net.TCPAddr).Port
	base := fmt.Sprintf("http://%s:%d", o.host, port)
	// Step 2: database and storage
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:proxy_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	store, err := memory.NewSecondaryStorage()
	if err != nil {
		t.Fatal(err)
	}
	// Step 3: plugins
	strategy := o.strategy
	if strategy == "" {
		strategy = socialconfig.StateDatabase
	}
	socialPlugin := social.New(socialconfig.SocialConfig{
		Providers: []providers.Provider{genericFake(fake, o.provider)}, StoreStateStrategy: strategy,
	})
	proxy := oauthproxy.New(o.proxy, oauthproxy.WithSocial(socialPlugin))
	cfg := config.AuthConfig{BaseURL: base, Secret: secret}
	if o.core != nil {
		o.core(&cfg)
	}
	// Step 4: goauth
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("oauth-proxy test", "test"))
	a, err := goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		Conn: db, SecondaryStorage: store, AuthConfig: cfg, Plugins: []plugin.Plugin{socialPlugin, proxy},
	})
	if err != nil {
		t.Fatalf("setup %s: %v", base, err)
	}
	ts.Config.Handler = mux
	ts.Start()
	t.Cleanup(ts.Close)
	return &deployment{URL: base, Auth: a, DB: db, Proxy: proxy}
}

// pair is a production deployment and a preview deployment proxying through it.
type pair struct {
	fake       *socialtest.Provider
	production *deployment
	preview    *deployment
	browser    *browser
}

// newPair starts the fake provider, production (127.0.0.1) and preview (localhost, ProductionURL =
// production). mut adjusts the preview options after the defaults.
func newPair(t *testing.T, strategy socialconfig.StateStrategy, mut ...func(prod, prev *deployOpts)) *pair {
	t.Helper()
	fake := socialtest.New(clientID, clientSecret)
	t.Cleanup(fake.Close)
	prodOpts := deployOpts{host: "127.0.0.1", strategy: strategy}
	prevOpts := deployOpts{host: "localhost", strategy: strategy}
	for _, m := range mut {
		m(&prodOpts, &prevOpts)
	}
	prod := deploy(t, fake, prodOpts)
	if prevOpts.proxy.ProductionURL == "" {
		prevOpts.proxy.ProductionURL = prod.URL
	}
	prev := deploy(t, fake, prevOpts)
	return &pair{fake: fake, production: prod, preview: prev, browser: newBrowser(t)}
}

// browser is a cookie-keeping HTTP client that does not follow redirects.
type browser struct {
	t      *testing.T
	jar    *cookiejar.Jar
	client *http.Client
}

func newBrowser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, jar: jar, client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

// response is a fully read response.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *response) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		t.Fatalf("decode %s: %v", r.Body, err)
	}
}

func (r *response) location() string { return r.Header.Get("Location") }

func (r *response) cookie(name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// do sends a request; a non-nil body is JSON. Origin is the target's origin for POSTs.
func (b *browser) do(method, target string, body any, headers ...string) *response {
	b.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		b.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		u, _ := url.Parse(target)
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return &response{Status: resp.StatusCode, Header: resp.Header, Body: raw}
}

func (b *browser) get(target string, headers ...string) *response {
	return b.do(http.MethodGet, target, nil, headers...)
}

// signIn posts /sign-in/social on d and returns the response and its provider URL.
func (b *browser) signIn(d *deployment, body map[string]any, headers ...string) (*response, string) {
	b.t.Helper()
	if _, ok := body["provider"]; !ok {
		body["provider"] = "fake"
	}
	res := b.do(http.MethodPost, d.URL+"/api/auth/sign-in/social", body, headers...)
	if res.Status != http.StatusOK {
		b.t.Fatalf("sign-in/social: %d %s", res.Status, res.Body)
	}
	var out struct {
		URL string `json:"url"`
	}
	res.json(b.t, &out)
	return res, out.URL
}

// authorize visits the provider URL and returns the callback URL it redirects to.
func (b *browser) authorize(providerURL string) string {
	b.t.Helper()
	res := b.get(providerURL)
	if res.Status != http.StatusFound {
		b.t.Fatalf("authorize: %d %s", res.Status, res.Body)
	}
	return res.location()
}

// flow runs a proxied sign-in on the preview: sign-in → provider → production callback → preview proxy
// callback. It returns the production callback response and the preview's final response.
func (p *pair) flow(t *testing.T, body map[string]any) (prodRes, prevRes *response) {
	t.Helper()
	_, providerURL := p.browser.signIn(p.preview, body)
	callback := p.browser.authorize(providerURL)
	if !strings.HasPrefix(callback, p.production.URL+"/api/auth/callback/fake?") {
		t.Fatalf("provider should redirect to production's callback, got %s", callback)
	}
	prodRes = p.browser.get(callback)
	if prodRes.Status != http.StatusFound {
		t.Fatalf("production callback: %d %s", prodRes.Status, prodRes.Body)
	}
	if !strings.HasPrefix(prodRes.location(), p.preview.URL+"/api/auth/oauth-proxy-callback?") {
		return prodRes, nil
	}
	prevRes = p.browser.get(prodRes.location())
	return prodRes, prevRes
}

// session returns the email of the browser's session on d ("" when signed out).
func (b *browser) session(d *deployment) string {
	b.t.Helper()
	res := b.get(d.URL + "/api/auth/get-session")
	var out struct {
		User *struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if res.Status != http.StatusOK {
		b.t.Fatalf("get-session: %d %s", res.Status, res.Body)
	}
	if string(bytes.TrimSpace(res.Body)) == "null" {
		return ""
	}
	res.json(b.t, &out)
	if out.User == nil {
		return ""
	}
	return out.User.Email
}

// countUsers counts the users of d.
func countUsers(t *testing.T, d *deployment) int64 {
	t.Helper()
	var n int64
	if err := d.DB.Model(&models.User{}).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// countVerifications counts the verification rows of d.
func countVerifications(t *testing.T, d *deployment) int64 {
	t.Helper()
	var n int64
	if err := d.DB.Model(&models.Verification{}).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// errorOf returns the `error` query parameter of a redirect location.
func errorOf(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse %s: %v", location, err)
	}
	return u.Query().Get("error")
}
