// Package compattest starts goauth in-process and compares responses with better-auth golden files.
package compattest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestSecret is shared with the TypeScript reference server when capturing golden files.
const TestSecret = "better-auth-secret-123456789012345678901234567890"

// Server is a goauth instance on an httptest server with a cookie-aware client.
type Server struct {
	URL    string
	Auth   *goauth.GoAuth
	DB     *gorm.DB
	API    huma.API
	Client *http.Client
	Jar    *cookiejar.Jar
	// Origin is sent on every request: the configured BaseURL, or the test server URL.
	Origin string
}

// Option customises the goauth options before setup.
type Option func(*goauth.GoAuthOptions)

// WithConfig mutates the AuthConfig (e.g. to switch Mode).
func WithConfig(fn func(*config.AuthConfig)) Option {
	return func(o *goauth.GoAuthOptions) { fn(&o.AuthConfig) }
}

// WithoutSecondaryStorage runs the server with the database only.
func WithoutSecondaryStorage() Option {
	return func(o *goauth.GoAuthOptions) { o.SecondaryStorage = nil }
}

// NewServer starts goauth on sqlite + in-memory secondary storage; it is closed on test cleanup.
func NewServer(t testing.TB, opts ...Option) *Server {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:compat_%s?mode=memory&cache=shared", uuid.NewString())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("compattest: open sqlite: %v", err)
	}
	store, err := memory.NewSecondaryStorage()
	if err != nil {
		t.Fatalf("compattest: secondary storage: %v", err)
	}

	o := goauth.GoAuthOptions{
		Conn:             db,
		SecondaryStorage: store,
		AuthConfig: config.AuthConfig{
			Secret: TestSecret,
		},
	}
	for _, opt := range opts {
		opt(&o)
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("goauth compat", "test"))
	a, err := goauth.SetupGoAuth(api, o)
	if err != nil {
		t.Fatalf("compattest: setup goauth: %v", err)
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	origin := o.BaseURL
	if origin == "" {
		origin = ts.URL
	}
	return &Server{
		URL:    ts.URL,
		Origin: origin,
		Auth:   a,
		DB:     db,
		API:    api,
		Jar:    jar,
		Client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

// Response is a fully-read HTTP response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the body into v.
func (r *Response) JSON(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		t.Fatalf("compattest: decode body: %v\n%s", err, r.Body)
	}
}

// Cookie returns the Set-Cookie entry named name, or nil.
func (r *Response) Cookie(name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Do sends a request; body is JSON-encoded unless it is nil or []byte.
func (s *Server) Do(t testing.TB, method, path string, body any, headers ...map[string]string) *Response {
	t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("compattest: encode body: %v", err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.URL+path, r)
	if err != nil {
		t.Fatalf("compattest: new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", s.Origin)
	for _, h := range headers {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		t.Fatalf("compattest: %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("compattest: read body: %v", err)
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: raw}
}

func (s *Server) Get(t testing.TB, path string, headers ...map[string]string) *Response {
	t.Helper()
	return s.Do(t, http.MethodGet, path, nil, headers...)
}

func (s *Server) Post(t testing.TB, path string, body any, headers ...map[string]string) *Response {
	t.Helper()
	return s.Do(t, http.MethodPost, path, body, headers...)
}
