// Package oidctest runs goauth as an OAuth / OpenID Connect provider in tests: the server's BaseURL is its
// own httptest URL (so discovery, issuer and redirect URLs are reachable), and Browser is a cookie-aware
// client that does not follow redirects. It is used by the oidc-provider and mcp tests and compat runners.
package oidctest

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
	"os"
	"strings"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Secret is the auth secret of test servers.
const Secret = "better-auth-secret-123456789012345678901234567890"

// Password is the password test users sign up with.
const Password = "Password123!"

// Server is a goauth instance whose BaseURL is its own URL.
type Server struct {
	// URL is the origin (also AuthConfig.BaseURL).
	URL string
	// Auth is the goauth instance.
	Auth *goauth.GoAuth
	// Mux serves goauth; tests may add their own routes (e.g. a login page or an MCP resource).
	Mux *http.ServeMux
	// DB is the database.
	DB *gorm.DB
	t  testing.TB
}

// Options configure NewServer.
type Options struct {
	// Plugins are installed in order.
	Plugins []plugin.Plugin
	// Configure adjusts the AuthConfig (BaseURL and Secret are set already).
	Configure func(*config.AuthConfig)
	// SecondaryStorage keeps sessions and verifications in an in-memory secondary storage too.
	SecondaryStorage bool
	// Listener is a listener from Listen (to know the URL before the server is set up); nil reserves one.
	Listener net.Listener
}

// Listen reserves a local address; pass it as Options.Listener. URL returns its origin.
func Listen(t testing.TB) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("oidctest: listen: %v", err)
	}
	return ln
}

// URL returns the origin of a reserved listener ("http://127.0.0.1:port").
func URL(ln net.Listener) string { return "http://" + ln.Addr().String() }

// NewServer starts goauth on a fresh in-memory SQLite database; GOAUTH_TEST_COLUMN_CASE=camel switches to
// better-auth's camelCase columns. The server is closed on test cleanup.
func NewServer(t testing.TB, o Options) *Server {
	t.Helper()
	// Step 1: reserve the address first so BaseURL is the server's own URL
	ts := httptest.NewUnstartedServer(nil)
	if o.Listener != nil {
		_ = ts.Listener.Close()
		ts.Listener = o.Listener
	}
	base := URL(ts.Listener)
	// Step 2: the database
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:oidc_%s?mode=memory&cache=shared", uuid.NewString())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("oidctest: open sqlite: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	// Step 3: goauth
	opts := goauth.GoAuthOptions{
		Conn:    db,
		Plugins: o.Plugins,
		AuthConfig: config.AuthConfig{
			BaseURL:        base,
			Secret:         Secret,
			TrustedOrigins: []string{base},
		},
	}
	if o.SecondaryStorage {
		store, err := memory.NewSecondaryStorage()
		if err != nil {
			t.Fatalf("oidctest: secondary storage: %v", err)
		}
		opts.SecondaryStorage = store
	}
	if cc := os.Getenv("GOAUTH_TEST_COLUMN_CASE"); cc != "" {
		opts.GoAuth.ColumnCase = schema.ColumnCase(cc)
	}
	if o.Configure != nil {
		o.Configure(&opts.AuthConfig)
	}
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("goauth oidc test", "test"))
	a, err := goauth.SetupGoAuth(context.Background(), api, opts)
	if err != nil {
		ts.Close()
		t.Fatalf("oidctest: setup goauth: %v", err)
	}
	// Step 4: serve
	ts.Config.Handler = mux
	ts.Start()
	t.Cleanup(ts.Close)
	return &Server{URL: base, Auth: a, Mux: mux, DB: db, t: t}
}

// Path returns the absolute URL of an auth endpoint ("/oauth2/token" → "<URL>/api/auth/oauth2/token").
func (s *Server) Path(p string) string { return s.URL + "/api/auth" + p }

// Browser returns a new cookie-aware client (redirects are not followed).
func (s *Server) Browser() *Browser {
	jar, _ := cookiejar.New(nil)
	return &Browser{s: s, Client: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Browser is a user agent with its own cookies.
type Browser struct {
	s *Server
	// Client is the HTTP client (cookie jar, no redirect following).
	Client *http.Client
	// Headers are sent with every request.
	Headers map[string]string
}

// Response is a fully read response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the body as a JSON object.
func (r *Response) JSON() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	return m
}

// Location returns the Location header parsed (nil when missing or invalid).
func (r *Response) Location() *url.URL {
	u, err := url.Parse(r.Header.Get("Location"))
	if err != nil || r.Header.Get("Location") == "" {
		return nil
	}
	return u
}

// Cookie returns the Set-Cookie entry named name.
func (r *Response) Cookie(name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// String describes the response for failure messages.
func (r *Response) String() string {
	return fmt.Sprintf("%d %v %s", r.Status, r.Header, r.Body)
}

// Do sends a request; rawURL may be absolute or a path on the server. body is JSON-encoded unless it is
// nil, url.Values (form) or []byte.
func (b *Browser) Do(method, rawURL string, body any, headers ...map[string]string) *Response {
	b.s.t.Helper()
	// Step 1: the body
	var rd io.Reader
	contentType := ""
	switch v := body.(type) {
	case nil:
	case url.Values:
		rd, contentType = strings.NewReader(v.Encode()), "application/x-www-form-urlencoded"
	case []byte:
		rd = bytes.NewReader(v)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			b.s.t.Fatalf("oidctest: encode body: %v", err)
		}
		rd, contentType = bytes.NewReader(raw), "application/json"
	}
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = b.s.URL + rawURL
	}
	req, err := http.NewRequest(method, rawURL, rd)
	if err != nil {
		b.s.t.Fatalf("oidctest: new request: %v", err)
	}
	// Step 2: headers (Origin of the server for mutating requests, like a browser on the app)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method != http.MethodGet && strings.HasPrefix(rawURL, b.s.URL) {
		req.Header.Set("Origin", b.s.URL)
	}
	for k, v := range b.Headers {
		req.Header.Set(k, v)
	}
	for _, h := range headers {
		for k, v := range h {
			if v == "" {
				req.Header.Del(k)
				continue
			}
			req.Header.Set(k, v)
		}
	}
	// Step 3: send and read
	res, err := b.Client.Do(req)
	if err != nil {
		b.s.t.Fatalf("oidctest: %s %s: %v", method, rawURL, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return &Response{Status: res.StatusCode, Header: res.Header, Body: raw}
}

// Get sends a GET.
func (b *Browser) Get(rawURL string, headers ...map[string]string) *Response {
	b.s.t.Helper()
	return b.Do(http.MethodGet, rawURL, nil, headers...)
}

// Post sends a POST.
func (b *Browser) Post(rawURL string, body any, headers ...map[string]string) *Response {
	b.s.t.Helper()
	return b.Do(http.MethodPost, rawURL, body, headers...)
}

// SignUp creates a user and signs the browser in; it returns the user ID.
func (b *Browser) SignUp(email, name string) string {
	b.s.t.Helper()
	r := b.Post("/api/auth/sign-up/email", map[string]any{"email": email, "password": Password, "name": name})
	if r.Status != http.StatusOK {
		b.s.t.Fatalf("oidctest: sign-up %s: %s", email, r)
	}
	user, _ := r.JSON()["user"].(map[string]any)
	id, _ := user["id"].(string)
	return id
}

// SignIn signs the browser in with email and Password and returns the response (the after hook may
// replace it with the authorization redirect).
func (b *Browser) SignIn(email string, headers ...map[string]string) *Response {
	b.s.t.Helper()
	return b.Post("/api/auth/sign-in/email", map[string]any{"email": email, "password": Password}, headers...)
}
