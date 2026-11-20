package test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/scim"
	scimconfig "github.com/better-go-auth/goauth/src/plugins/scim/config"
	"github.com/better-go-auth/goauth/src/plugins/scim/services"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	baseURL  = "http://localhost:3000"
	authBase = baseURL + "/api/auth"
)

// env is one goauth server with the scim plugin.
type env struct {
	s    *compattest.Server
	scim *scim.Plugin
	org  *org.OrgPlugin
}

type envOpts struct {
	scim    func(c *scimconfig.SCIMConfig)
	core    func(c *config.AuthConfig)
	withOrg bool
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	// Step 1: the plugins
	cfg := scimconfig.SCIMConfig{}
	if o.scim != nil {
		o.scim(&cfg)
	}
	e := &env{scim: scim.New(cfg)}
	opts := []compattest.Option{compattest.WithPlugin(e.scim), compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = baseURL
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		if o.core != nil {
			o.core(c)
		}
	})}
	if o.withOrg {
		db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:scim_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatal(err)
		}
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.SetMaxOpenConns(1)
		}
		op, err := org.NewWithGorm(db, orgconfig.OrgConfig{})
		if err != nil {
			t.Fatal(err)
		}
		e.org = op
		opts = append(opts, compattest.WithDB(db), compattest.WithPlugin(op))
	}
	// Step 2: the server
	e.s = compattest.NewServer(t, opts...)
	return e
}

// signUp creates a user and leaves its session in the jar.
func (e *env) signUp(t *testing.T, email string) string {
	t.Helper()
	r := e.s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": "password1234", "name": "Admin"})
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

// freshBrowser replaces the cookie jar.
func (e *env) freshBrowser() {
	jar, _ := cookiejar.New(nil)
	e.s.Client.Jar = jar
}

// generate posts /scim/generate-token.
func (e *env) generate(t *testing.T, body map[string]any) *compattest.Response {
	t.Helper()
	return e.s.Post(t, "/api/auth/scim/generate-token", body)
}

// mustToken generates a token and fails the test otherwise.
func (e *env) mustToken(t *testing.T, providerID, orgID string) string {
	t.Helper()
	body := map[string]any{"providerId": providerID}
	if orgID != "" {
		body["organizationId"] = orgID
	}
	r := e.generate(t, body)
	if r.Status != http.StatusCreated {
		t.Fatalf("generate-token: %d %s", r.Status, r.Body)
	}
	var out struct {
		SCIMToken string `json:"scimToken"`
	}
	r.JSON(t, &out)
	return out.SCIMToken
}

// scimDo sends a SCIM request (no cookies, application/scim+json) with the bearer token.
func (e *env) scimDo(t *testing.T, method, path, token string, body any) *compattest.Response {
	t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.s.URL+"/api/auth"+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return &compattest.Response{Status: resp.StatusCode, Header: resp.Header, Body: raw}
}

// scimErr asserts the RFC 7644 error body exactly.
func scimErr(t *testing.T, r *compattest.Response, status int, detail, scimType string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("expected %d, got %d: %s", status, r.Status, r.Body)
	}
	want := map[string]any{"schemas": []any{services.SCIMErrorSchema}, "status": fmt.Sprint(status), "detail": detail}
	if scimType != "" {
		want["scimType"] = scimType
	}
	var got map[string]any
	r.JSON(t, &got)
	if len(got) != len(want) {
		t.Fatalf("error body %s, want %v", r.Body, want)
	}
	for k, v := range want {
		if fmt.Sprint(got[k]) != fmt.Sprint(v) {
			t.Fatalf("error body %s, want %v", r.Body, want)
		}
	}
}

// apiErr asserts a better-auth {code?, message} error.
func apiErr(t *testing.T, r *compattest.Response, status int, code, message string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("expected %d, got %d: %s", status, r.Status, r.Body)
	}
	var out struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	r.JSON(t, &out)
	if out.Code != code || (message != "" && out.Message != message) {
		t.Fatalf("expected %s %q, got %s", code, message, r.Body)
	}
}

// decodeToken splits a SCIM token.
func decodeToken(t *testing.T, token string) []string {
	t.Helper()
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token %q is not padded base64url: %v", token, err)
	}
	return strings.Split(string(raw), ":")
}

// encode builds a SCIM bearer token from its raw "<secret>:<providerId>[:<organizationId>]" form.
func encode(raw string) string { return base64.URLEncoding.EncodeToString([]byte(raw)) }

// userByEmail loads a user (nil when missing).
func (e *env) userByEmail(email string) *models.User {
	u, err := e.s.Auth.Repositories().FindUserByEmail(context.Background(), email)
	if err != nil {
		return nil
	}
	return u
}

// providerRow loads a stored scimProvider row.
func (e *env) providerRow(t *testing.T, providerID string) adapter.Record {
	t.Helper()
	r, err := e.s.Auth.Adapter().FindOne(context.Background(), services.Model, []adapter.Where{{Field: "providerId", Value: providerID}})
	if err != nil {
		return nil
	}
	return r
}

// createOrg creates an organization owned by the signed-in user.
func (e *env) createOrg(t *testing.T, slug string) string {
	t.Helper()
	r := e.s.Post(t, "/api/auth/organization/create", map[string]any{"name": slug, "slug": slug})
	if r.Status != http.StatusOK {
		t.Fatalf("create org: %d %s", r.Status, r.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	r.JSON(t, &out)
	return out.ID
}

// userBody is a SCIM user.
func userBody(userName string, extra map[string]any) map[string]any {
	b := map[string]any{"userName": userName, "name": map[string]any{"givenName": "Ada", "familyName": "Lovelace"}}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

// resource decodes a SCIM user resource.
func resource(t *testing.T, r *compattest.Response) map[string]any {
	t.Helper()
	var out map[string]any
	r.JSON(t, &out)
	return out
}
