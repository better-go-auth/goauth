package test

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/config"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/schema"
)

// columns lists the columns of a table.
func columns(t *testing.T, e *env, table string) []string {
	t.Helper()
	cols, err := e.srv.DB.Migrator().ColumnTypes(table)
	if err != nil {
		t.Fatalf("columns of %s: %v", table, err)
	}
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.Name()
	}
	return out
}

// TestColumnCases runs a token exchange with snake_case and camelCase columns and checks the tables.
func TestColumnCases(t *testing.T) {
	want := map[schema.ColumnCase]map[string][]string{
		schema.Snake: {
			"oauthApplication": {"id", "name", "icon", "metadata", "client_id", "client_secret", "redirect_urls", "type", "disabled", "user_id", "created_at", "updated_at"},
			"oauthAccessToken": {"id", "access_token", "refresh_token", "access_token_expires_at", "refresh_token_expires_at", "client_id", "user_id", "scopes", "created_at", "updated_at"},
			"oauthConsent":     {"id", "client_id", "user_id", "scopes", "created_at", "updated_at", "consent_given"},
		},
		schema.Camel: {
			"oauthApplication": {"id", "name", "icon", "metadata", "clientId", "clientSecret", "redirectUrls", "type", "disabled", "userId", "createdAt", "updatedAt"},
			"oauthAccessToken": {"id", "accessToken", "refreshToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "clientId", "userId", "scopes", "createdAt", "updatedAt"},
			"oauthConsent":     {"id", "clientId", "userId", "scopes", "createdAt", "updatedAt", "consentGiven"},
		},
	}
	for cc, tables := range want {
		t.Run(string(cc), func(t *testing.T) {
			e := newEnvWith(t, oidcconfig.Config{ConsentPage: consentPage}, func(c *config.AuthConfig) { c.GoAuth.ColumnCase = cc })
			// Step 1: the tables have better-auth's columns in the configured case
			for table, cols := range tables {
				got := columns(t, e, table)
				for _, c := range cols {
					if !slices.Contains(got, c) {
						t.Fatalf("%s: column %s missing in %v", table, c, got)
					}
				}
			}
			// Step 2: register → consent → token → userinfo works on that layout
			b := e.srv.Browser()
			b.SignUp("case@example.com", "Case")
			cl := e.register(b)
			b.Get(e.authorizeURL(map[string]string{"response_type": "code", "client_id": cl.ID, "redirect_uri": rpCallback, "scope": "openid email offline_access"}))
			r := b.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true})
			code, _ := codeFrom(t, r.JSON()["redirectURI"].(string))
			tok := e.token(e.srv.Browser(), url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}}, basic(cl.ID, cl.Secret))
			if tok.Status != http.StatusOK {
				t.Fatalf("token: %s", tok)
			}
			ui := e.srv.Browser().Get(e.srv.Path("/oauth2/userinfo"), map[string]string{"Authorization": "Bearer " + tok.JSON()["access_token"].(string)})
			if ui.JSON()["email"] != "case@example.com" {
				t.Fatalf("userinfo: %s", ui)
			}
			ref := e.token(e.srv.Browser(), url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.JSON()["refresh_token"].(string)}}, basic(cl.ID, cl.Secret))
			if ref.Status != http.StatusOK {
				t.Fatalf("refresh: %s", ref)
			}
		})
	}
}

// TestSchemaRenames: the plugin's schema option renames tables and columns.
func TestSchemaRenames(t *testing.T) {
	e := newEnv(t, oidcconfig.Config{ConsentPage: consentPage, Schema: map[string]oidcconfig.ModelSchemaOptions{
		oidcconfig.ModelOAuthApplication: {ModelName: "oauth_clients", Fields: map[string]string{"clientId": "client_identifier"}},
		oidcconfig.ModelOAuthConsent:     {ModelName: "oauth_consents"},
	}})
	if got := columns(t, e, "oauth_clients"); !slices.Contains(got, "client_identifier") {
		t.Fatalf("renamed column missing: %v", got)
	}
	b := e.srv.Browser()
	b.SignUp("ren@example.com", "Ren")
	cl := e.register(b)
	b.Get(e.authorizeURL(map[string]string{"response_type": "code", "client_id": cl.ID, "redirect_uri": rpCallback}))
	if r := b.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true}); r.Status != http.StatusOK {
		t.Fatalf("consent: %s", r)
	}
	var n int64
	e.srv.DB.Table("oauth_consents").Count(&n)
	if n != 1 {
		t.Fatalf("consents in renamed table: %d", n)
	}
}

// TestDisabledOps: better-auth endpoint keys turn routes off.
func TestDisabledOps(t *testing.T) {
	e := newEnvWith(t, oidcconfig.Config{}, func(c *config.AuthConfig) {
		c.DisabledOps = []consts.OperationId{"registerOAuthApplication", "endSession"}
	})
	b := e.srv.Browser()
	b.SignUp("off@example.com", "Off")
	if r := b.Post(e.srv.Path("/oauth2/register"), map[string]any{"redirect_uris": []string{rpCallback}}); r.Status != http.StatusNotFound && r.Status != http.StatusMethodNotAllowed {
		t.Fatalf("disabled register: %s", r)
	}
	if r := b.Get(e.srv.Path("/oauth2/endsession")); r.Status != http.StatusNotFound && r.Status != http.StatusMethodNotAllowed {
		t.Fatalf("disabled endsession GET: %s", r)
	}
	if r := b.Post(e.srv.Path("/oauth2/endsession"), nil); r.Status != http.StatusOK {
		t.Fatalf("endsession POST stays: %s", r)
	}
}
