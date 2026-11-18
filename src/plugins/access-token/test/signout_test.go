package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const testBaseURL = "http://localhost:8080"

// httpEnv is a full goauth server (core routes + access-token plugin) for HTTP-level tests.
type httpEnv struct {
	t   *testing.T
	url string
	db  *gorm.DB
}

type httpResp struct {
	status int
	header http.Header
	body   []byte
}

// cookie returns the Set-Cookie entry named name, or nil.
func (r *httpResp) cookie(name string) *http.Cookie {
	for _, ck := range (&http.Response{Header: r.header}).Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

// newHTTPEnv mounts goauth with the access-token plugin and a route protected by the plugin's AuthMiddleware.
func newHTTPEnv(t *testing.T, autoRegister bool) *httpEnv {
	t.Helper()
	// Step 1: a private in-memory database and secondary storage
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:at_signout_%s?mode=memory&cache=shared", uuid.NewString())),
		&gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
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
	// Step 2: goauth with the access-token plugin
	at := accesstoken.New(accesstokenconfig.AccessTokenConfig{AutoRegisterMiddleware: autoRegister})
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("access-token sign-out test", "1.0.0"))
	a, err := goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		Conn:             db,
		SecondaryStorage: store,
		Plugins:          []plugin.Plugin{at},
		AuthConfig: config.AuthConfig{
			BaseURL: testBaseURL,
			Secret:  "access-token-signout-test-secret-32-bytes!",
			EmailVerification: config.EmailVerification{
				GoAuth: config.EmailVerificationGoAuth{CodeExpiresIn: 15 * time.Minute, CodeSender: &mockEmailSender{}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Step 3: a route of the app that accepts access JWTs
	huma.Register(api, huma.Operation{
		OperationID: "Test_JWTMe",
		Method:      http.MethodGet,
		Path:        "/api/test/jwt/me",
		Middlewares: huma.Middlewares{at.AuthMiddleware(), a.MiddlewareInt().Authenticate()},
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body struct{ UserID string } }, error) {
		s, ok := authenticator.SessionFromContext(ctx)
		if !ok {
			return nil, huma.Error401Unauthorized("not signed in")
		}
		out := &struct{ Body struct{ UserID string } }{}
		out.Body.UserID = s.Session.UserID
		return out, nil
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return &httpEnv{t: t, url: ts.URL, db: db}
}

// do sends a request without any cookie jar; headers are set verbatim (Origin is always the trusted base URL).
func (e *httpEnv) do(method, path string, body any, headers map[string]string) *httpResp {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, e.url+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return &httpResp{status: resp.StatusCode, header: resp.Header, body: raw}
}

// signUpAndLogin registers email through /signup and logs in through /login, returning the token pair.
func (e *httpEnv) signUpAndLogin(email string) (access, refresh string) {
	e.t.Helper()
	if r := e.do(http.MethodPost, "/api/auth/signup", map[string]any{
		"fName": "Sign", "email": email, "password": "Password123!",
	}, nil); r.status != http.StatusCreated {
		e.t.Fatalf("signup: %d %s", r.status, r.body)
	}
	r := e.do(http.MethodPost, "/api/auth/login", map[string]any{"info": email, "password": "Password123!"}, nil)
	if r.status != http.StatusCreated {
		e.t.Fatalf("login: %d %s", r.status, r.body)
	}
	var out struct {
		Body struct {
			AuthTokens struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			} `json:"authTokens"`
		} `json:"body"`
	}
	if err := json.Unmarshal(r.body, &out); err != nil {
		e.t.Fatal(err)
	}
	return out.Body.AuthTokens.AccessToken, out.Body.AuthTokens.RefreshToken
}

// expectRevoked asserts the access JWT and the refresh token of a signed-out session no longer work.
func (e *httpEnv) expectRevoked(access, refresh string) {
	e.t.Helper()
	if r := e.do(http.MethodGet, "/api/test/jwt/me", nil, map[string]string{"Authorization": "Bearer " + access}); r.status != http.StatusUnauthorized {
		e.t.Fatalf("access JWT after sign-out: %d, want 401: %s", r.status, r.body)
	}
	if r := e.do(http.MethodPost, "/api/auth/refresh", map[string]any{"token": refresh}, nil); r.status != http.StatusUnauthorized {
		e.t.Fatalf("refresh after sign-out: %d, want 401: %s", r.status, r.body)
	}
}

// expectPluginCookiesExpired asserts the sign-out response deletes the access-token and refresh-token cookies.
func expectPluginCookiesExpired(t *testing.T, r *httpResp) {
	t.Helper()
	for _, name := range []string{"access-token", "refresh-token"} {
		ck := r.cookie(name)
		if ck == nil || ck.Value != "" || ck.MaxAge >= 0 {
			t.Fatalf("sign-out must expire the %s cookie, got %+v (Set-Cookie: %v)", name, ck, r.header.Values("Set-Cookie"))
		}
	}
}

func TestSignOut_WithAccessTokenCredentials(t *testing.T) {
	cases := []struct {
		name         string
		autoRegister bool
		headers      func(access, refresh string) map[string]string
	}{
		{"bearer access JWT", false, func(access, _ string) map[string]string {
			return map[string]string{"Authorization": "Bearer " + access}
		}},
		{"bearer access JWT with AutoRegisterMiddleware", true, func(access, _ string) map[string]string {
			return map[string]string{"Authorization": "Bearer " + access}
		}},
		{"bearer refresh token", false, func(_, refresh string) map[string]string {
			return map[string]string{"Authorization": "Bearer " + refresh}
		}},
		{"refresh-token cookie only", false, func(_, refresh string) map[string]string {
			// cookie requests are browser requests: core checks their Origin
			return map[string]string{"Cookie": "refresh-token=" + refresh, "Origin": testBaseURL}
		}},
		{"access-token cookie only", false, func(access, _ string) map[string]string {
			return map[string]string{"Cookie": "access-token=" + access, "Origin": testBaseURL}
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newHTTPEnv(t, tc.autoRegister)
			// Step 1: /login, and the access JWT works on the app's protected route
			access, refresh := e.signUpAndLogin(fmt.Sprintf("signout%d@example.com", i))
			if r := e.do(http.MethodGet, "/api/test/jwt/me", nil, map[string]string{"Authorization": "Bearer " + access}); r.status != http.StatusOK {
				t.Fatalf("access JWT before sign-out: %d %s", r.status, r.body)
			}
			// Step 2: log out through the core sign-out route
			r := e.do(http.MethodPost, "/api/auth/sign-out", nil, tc.headers(access, refresh))
			if r.status != http.StatusOK || !strings.Contains(string(r.body), `"success":true`) {
				t.Fatalf("sign-out: %d %s", r.status, r.body)
			}
			// Step 3: the session is gone and the plugin cookies are expired
			e.expectRevoked(access, refresh)
			expectPluginCookiesExpired(t, r)
		})
	}
}

func TestSignOut_WithoutAccessTokenCredentials(t *testing.T) {
	e := newHTTPEnv(t, false)
	access, refresh := e.signUpAndLogin("nocreds@example.com")
	// Step 1: sign-out without credentials still answers like better-auth, without touching plugin cookies
	r := e.do(http.MethodPost, "/api/auth/sign-out", nil, map[string]string{"Origin": testBaseURL})
	if r.status != http.StatusOK {
		t.Fatalf("sign-out: %d %s", r.status, r.body)
	}
	if r.cookie("access-token") != nil || r.cookie("refresh-token") != nil {
		t.Fatalf("plugin cookies must not be touched without access-token credentials: %v", r.header.Values("Set-Cookie"))
	}
	// Step 2: a tampered access JWT revokes nothing
	r = e.do(http.MethodPost, "/api/auth/sign-out", nil, map[string]string{"Authorization": "Bearer " + access[:len(access)-4] + "AAAA"})
	if r.status != http.StatusOK {
		t.Fatalf("sign-out with tampered JWT: %d %s", r.status, r.body)
	}
	if r := e.do(http.MethodPost, "/api/auth/refresh", map[string]any{"token": refresh}, nil); r.status != http.StatusCreated {
		t.Fatalf("session must survive a sign-out without valid credentials: %d %s", r.status, r.body)
	}
}

func TestSignup_Validation(t *testing.T) {
	e := newHTTPEnv(t, false)
	cases := []struct {
		name string
		body map[string]any
	}{
		{"invalid email", map[string]any{"fName": "Al", "email": "not-an-email", "password": "Password123!"}},
		{"display-name email", map[string]any{"fName": "Al", "email": "Al <al@example.com>", "password": "Password123!"}},
		{"short password", map[string]any{"fName": "Al", "email": "short@example.com", "password": "short"}},
		{"long password", map[string]any{"fName": "Al", "email": "long@example.com", "password": strings.Repeat("p", 129)}},
		{"missing password", map[string]any{"fName": "Al", "email": "nopw@example.com"}},
		{"missing first name", map[string]any{"email": "nofn@example.com", "password": "Password123!"}},
	}
	for _, tc := range cases {
		if r := e.do(http.MethodPost, "/api/auth/signup", tc.body, nil); r.status != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400: %s", tc.name, r.status, r.body)
		}
	}

	// lName and avatar are optional; an absent avatar is stored as NULL and the email lower-cased
	r := e.do(http.MethodPost, "/api/auth/signup", map[string]any{"fName": "Al", "email": "Valid@Example.com", "password": "Password123!"}, nil)
	if r.status != http.StatusCreated || !strings.Contains(string(r.body), `"status":201`) {
		t.Fatalf("valid signup: %d %s", r.status, r.body)
	}
	var u models.User
	if err := e.db.Where("email = ?", "valid@example.com").First(&u).Error; err != nil {
		t.Fatalf("user not stored lower-cased: %v", err)
	}
	if u.Image != nil {
		t.Fatalf("absent avatar must be stored as NULL, got %q", *u.Image)
	}
	// the account signs in with the mixed-case address
	if r := e.do(http.MethodPost, "/api/auth/login", map[string]any{"info": "Valid@Example.com", "password": "Password123!"}, nil); r.status != http.StatusCreated {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
}

// TestSignOut_WithAnotherSessionCookie covers a request that carries both a better-auth session cookie
// (of another session) and access-token credentials: core signs the cookie session out and the plugin
// revokes the access-token session too, but only when core accepted the request (origin check).
func TestSignOut_WithAnotherSessionCookie(t *testing.T) {
	e := newHTTPEnv(t, false)
	// Step 1: a better-auth session (cookie) and an access-token session of another user
	r := e.do(http.MethodPost, "/api/auth/sign-up/email", map[string]any{
		"email": "cookie-user@example.com", "password": "Password123!", "name": "Cookie",
	}, map[string]string{"Origin": testBaseURL})
	if r.status != http.StatusOK {
		t.Fatalf("sign-up: %d %s", r.status, r.body)
	}
	sessionCookie := r.cookie("better-auth.session_token")
	if sessionCookie == nil {
		t.Fatalf("no session cookie: %v", r.header.Values("Set-Cookie"))
	}
	access, refresh := e.signUpAndLogin("other-session@example.com")
	cookieHeader := sessionCookie.Name + "=" + sessionCookie.Value + "; refresh-token=" + refresh

	// Step 2: a cross-site request is rejected by core and revokes nothing
	r = e.do(http.MethodPost, "/api/auth/sign-out", nil, map[string]string{"Cookie": cookieHeader, "Origin": "https://evil.example"})
	if r.status < http.StatusBadRequest {
		t.Fatalf("cross-site sign-out: %d, want an error: %s", r.status, r.body)
	}
	if r := e.do(http.MethodGet, "/api/test/jwt/me", nil, map[string]string{"Authorization": "Bearer " + access}); r.status != http.StatusOK {
		t.Fatalf("access-token session must survive a rejected sign-out: %d %s", r.status, r.body)
	}

	// Step 3: from the trusted origin both sessions are signed out
	r = e.do(http.MethodPost, "/api/auth/sign-out", nil, map[string]string{"Cookie": cookieHeader, "Origin": testBaseURL})
	if r.status != http.StatusOK {
		t.Fatalf("sign-out: %d %s", r.status, r.body)
	}
	e.expectRevoked(access, refresh)
	if r := e.do(http.MethodGet, "/api/auth/get-session", nil, map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}); string(bytes.TrimSpace(r.body)) != "null" {
		t.Fatalf("cookie session after sign-out: %d %s", r.status, r.body)
	}
}
