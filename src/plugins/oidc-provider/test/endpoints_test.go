package test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
	"github.com/golang-jwt/jwt/v5"
)

func TestUserInfo(t *testing.T) {
	var seenScopes []string
	c := newCodeEnv(t, oidcconfig.Config{
		GetAdditionalUserInfoClaim: func(_ context.Context, u *models.User, scopes []string, cl *oidcconfig.Client) (map[string]any, error) {
			seenScopes = scopes
			return map[string]any{"tenant": "acme", "client": cl.ClientID, "name": strings.ToUpper(u.Name)}, nil
		},
	})
	rp := c.srv.Browser()
	bearer := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

	// Step 1: header and token errors
	expectOAuthError(t, rp.Get(c.srv.Path("/oauth2/userinfo")), 401, "invalid_request", "authorization header not found")
	expectOAuthError(t, rp.Get(c.srv.Path("/oauth2/userinfo"), bearer("nope")), 401, "invalid_token", "invalid access token")

	// Step 2: openid only → sub plus the additional claims
	tok := c.exchange(c.code(map[string]string{"scope": "openid"}), nil).JSON()
	r := rp.Get(c.srv.Path("/oauth2/userinfo"), bearer(tok["access_token"].(string)))
	m := r.JSON()
	if r.Status != 200 || m["sub"] != c.userID || m["email"] != nil || m["tenant"] != "acme" || m["client"] != trusted.ClientID || m["name"] != "TEST USER" {
		t.Fatalf("openid userinfo: %s", r)
	}
	if _, ok := m["picture"]; ok || strings.Join(seenScopes, " ") != "openid" {
		t.Fatalf("profile claims without profile scope: %v %v", m, seenScopes)
	}
	// Step 3: the additional claims are also in the id_token
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(tok["id_token"].(string), claims, func(*jwt.Token) (any, error) { return []byte(trusted.ClientSecret), nil }); err != nil ||
		claims["tenant"] != "acme" {
		t.Fatalf("id_token additional claims: %v %v", claims, err)
	}
	// Step 4: picture is the user's image
	img := "https://img.example.com/u.png"
	if _, err := c.srv.Auth.Repositories().UpdateUser(context.Background(), c.userID, map[string]any{"image": img}); err != nil {
		t.Fatal(err)
	}
	tok = c.exchange(c.code(map[string]string{"scope": "openid profile"}), nil).JSON()
	m = rp.Get(c.srv.Path("/oauth2/userinfo"), bearer(tok["access_token"].(string))).JSON()
	if m["picture"] != img || m["given_name"] != "Test" || m["family_name"] != "User" {
		t.Fatalf("profile userinfo: %v", m)
	}
	// Step 5: an expired access token
	setTokenTime(t, c.env, "accessToken", tok["access_token"].(string), "accessTokenExpiresAt", time.Now().Add(-time.Second))
	expectOAuthError(t, rp.Get(c.srv.Path("/oauth2/userinfo"), bearer(tok["access_token"].(string))), 401, "invalid_token", "The Access Token expired")
	// Step 6: a failing claim function is an error
	f := newCodeEnv(t, oidcconfig.Config{GetAdditionalUserInfoClaim: func(context.Context, *models.User, []string, *oidcconfig.Client) (map[string]any, error) {
		return nil, errors.New("boom")
	}})
	if r := f.exchange(f.code(nil), nil); r.Status != 500 {
		t.Fatalf("failing claims at token: %s", r)
	}
}

func TestRegister(t *testing.T) {
	e := newEnv(t, oidcconfig.Config{})
	anon := e.srv.Browser()
	// Step 1: registration needs a session unless dynamic registration is allowed
	r := anon.Post(e.srv.Path("/oauth2/register"), map[string]any{"redirect_uris": []string{rpCallback}})
	if r.Status != 401 || r.JSON()["error"] != "invalid_token" || r.JSON()["error_description"] != "Authentication required for client registration" {
		t.Fatalf("anonymous: %s", r)
	}
	// Step 2: zod-style validation errors
	b := e.srv.Browser()
	userID := b.SignUp("reg@example.com", "Reg")
	validation := []struct {
		body any
		msg  string
	}{
		{nil, "[body] Invalid input: expected object, received undefined"},
		{map[string]any{}, "[body.redirect_uris] Invalid input: expected array, received undefined"},
		{map[string]any{"redirect_uris": []any{"javascript:alert(1)", 3}}, "[body.redirect_uris.0] redirect_uri cannot use a javascript:, data:, or vbscript: scheme; [body.redirect_uris.1] Invalid input: expected string, received number"},
		{map[string]any{"redirect_uris": []string{rpCallback}, "token_endpoint_auth_method": "private_key_jwt"}, `[body.token_endpoint_auth_method] Invalid option: expected one of "none"|"client_secret_basic"|"client_secret_post"`},
		{map[string]any{"redirect_uris": []string{rpCallback}, "grant_types": []string{"device_code"}}, `[body.grant_types.0] Invalid option: expected one of "authorization_code"|"implicit"|"password"|"client_credentials"|"refresh_token"|"urn:ietf:params:oauth:grant-type:jwt-bearer"|"urn:ietf:params:oauth:grant-type:saml2-bearer"`},
		{map[string]any{"redirect_uris": []string{rpCallback}, "metadata": []int{1}}, "[body.metadata] Invalid input: expected record, received array"},
	}
	for _, v := range validation {
		r := b.Post(e.srv.Path("/oauth2/register"), v.body)
		if r.Status != 400 || r.JSON()["code"] != "VALIDATION_ERROR" || r.JSON()["message"] != v.msg {
			t.Fatalf("body %v: %s", v.body, r)
		}
	}
	// Step 3: RFC 7591 consistency rules
	r = b.Post(e.srv.Path("/oauth2/register"), map[string]any{"redirect_uris": []string{}})
	expectOAuthError(t, r, 400, "invalid_redirect_uri", "Redirect URIs are required for authorization_code and implicit grant types")
	r = b.Post(e.srv.Path("/oauth2/register"), map[string]any{"redirect_uris": []string{rpCallback}, "response_types": []string{"token"}})
	expectOAuthError(t, r, 400, "invalid_client_metadata", "When 'authorization_code' grant type is used, 'code' response type must be included")
	r = b.Post(e.srv.Path("/oauth2/register"), map[string]any{"redirect_uris": []string{rpCallback}, "grant_types": []string{"implicit"}})
	expectOAuthError(t, r, 400, "invalid_client_metadata", "When 'implicit' grant type is used, 'token' response type must be included")
	// Step 4: success: 201, no-store, the echo of the metadata, the stored row
	r = b.Post(e.srv.Path("/oauth2/register"), map[string]any{
		"redirect_uris": []string{rpCallback, "https://rp.example.com/cb2"}, "client_name": "My RP", "logo_uri": "https://rp.example.com/logo.png",
		"scope": "openid email", "contacts": []string{"ops@rp.example.com"}, "metadata": map[string]any{"tier": "gold"},
		"token_endpoint_auth_method": "client_secret_post", "software_id": "rp-1",
	})
	m := r.JSON()
	if r.Status != 201 || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("register: %s", r)
	}
	if m["client_secret_expires_at"] != float64(0) || m["token_endpoint_auth_method"] != "client_secret_post" || m["client_name"] != "My RP" ||
		m["software_id"] != "rp-1" || m["metadata"].(map[string]any)["tier"] != "gold" || len(m["client_id"].(string)) != 32 || len(m["client_secret"].(string)) != 32 ||
		strings.Join(toStrings(m["grant_types"]), ",") != "authorization_code" || strings.Join(toStrings(m["response_types"]), ",") != "code" {
		t.Fatalf("register body: %v", m)
	}
	if _, ok := m["client_uri"]; ok {
		t.Fatalf("undefined members must be left out: %v", m)
	}
	rec, err := e.p.Service().Store().FindOne(context.Background(), oidcconfig.ModelOAuthApplication, []adapter.Where{{Field: "clientId", Value: m["client_id"]}})
	if err != nil || rec == nil || rec["type"] != "web" || rec["userId"] != userID || rec["redirectUrls"] != rpCallback+",https://rp.example.com/cb2" ||
		rec["clientSecret"] != m["client_secret"] || rec["icon"] != "https://rp.example.com/logo.png" || rec["metadata"] != `{"tier":"gold"}` || rec["disabled"] != false {
		t.Fatalf("stored client: %v %v", rec, err)
	}
	// Step 5: the public info of the client (session required, 404 for unknown ids)
	if r := anon.Get(e.srv.Path("/oauth2/client/" + m["client_id"].(string))); r.Status != 401 {
		t.Fatalf("client info without session: %s", r)
	}
	r = b.Get(e.srv.Path("/oauth2/client/" + m["client_id"].(string)))
	if r.Status != 200 || r.JSON()["icon"] != "https://rp.example.com/logo.png" || r.JSON()["name"] != "My RP" {
		t.Fatalf("client info: %s", r)
	}
	expectOAuthError(t, b.Get(e.srv.Path("/oauth2/client/ghost")), 404, "not_found", "client not found")

	// Step 6: dynamic registration without a session, custom generators
	d := newEnv(t, oidcconfig.Config{AllowDynamicClientRegistration: true,
		GenerateClientID: func() string { return "fixed-id" }, GenerateClientSecret: func() string { return "fixed-secret" }})
	r = d.srv.Browser().Post(d.srv.Path("/oauth2/register"), map[string]any{"redirect_uris": []string{rpCallback}, "client_name": "Dyn"})
	if r.Status != 201 || r.JSON()["client_id"] != "fixed-id" || r.JSON()["client_secret"] != "fixed-secret" {
		t.Fatalf("dynamic: %s", r)
	}
	// Step 7: the public info of a trusted client has a null icon
	tc := newCodeEnv(t, oidcconfig.Config{})
	r = tc.user.Get(tc.srv.Path("/oauth2/client/" + trusted.ClientID))
	if r.Status != 200 || string(r.Body) != `{"clientId":"trusted-app","name":"Trusted App","icon":null}`+"\n" {
		t.Fatalf("trusted client info: %s", r)
	}
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, len(arr))
	for i, x := range arr {
		out[i], _ = x.(string)
	}
	return out
}

// TestStoreClientSecret registers clients with every storage mode and runs a token exchange with each.
func TestStoreClientSecret(t *testing.T) {
	modes := []struct {
		name    string
		storage oidcconfig.ClientSecretStorage
		check   func(t *testing.T, stored, plain string)
	}{
		{"plain", oidcconfig.ClientSecretStorage{}, func(t *testing.T, stored, plain string) {
			if stored != plain {
				t.Fatalf("plain stored %q", stored)
			}
		}},
		{"hashed", oidcconfig.ClientSecretStorage{Mode: oidcconfig.SecretHashed}, func(t *testing.T, stored, plain string) {
			if stored != services.S256(plain) {
				t.Fatalf("hashed stored %q", stored)
			}
		}},
		{"encrypted", oidcconfig.ClientSecretStorage{Mode: oidcconfig.SecretEncrypted}, func(t *testing.T, stored, plain string) {
			if stored == plain || len(stored) < 40 {
				t.Fatalf("encrypted stored %q", stored)
			}
		}},
		{"custom hash", oidcconfig.ClientSecretStorage{Hash: func(_ context.Context, s string) (string, error) { return "h:" + s, nil }},
			func(t *testing.T, stored, plain string) {
				if stored != "h:"+plain {
					t.Fatalf("custom hash stored %q", stored)
				}
			}},
		{"custom encrypt", oidcconfig.ClientSecretStorage{
			Encrypt: func(_ context.Context, s string) (string, error) { return reverse(s), nil },
			Decrypt: func(_ context.Context, s string) (string, error) { return reverse(s), nil },
		}, func(t *testing.T, stored, plain string) {
			if stored != reverse(plain) {
				t.Fatalf("custom encrypt stored %q", stored)
			}
		}},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			e := newEnv(t, oidcconfig.Config{StoreClientSecret: m.storage, ConsentPage: consentPage})
			b := e.srv.Browser()
			b.SignUp("s@example.com", "S")
			cl := e.register(b)
			rec, _ := e.p.Service().Store().FindOne(context.Background(), oidcconfig.ModelOAuthApplication, []adapter.Where{{Field: "clientId", Value: cl.ID}})
			m.check(t, rec["clientSecret"].(string), cl.Secret)
			// the stored form verifies the plain secret at the token endpoint (wrong secrets fail)
			b.Get(e.authorizeURL(map[string]string{"response_type": "code", "client_id": cl.ID, "redirect_uri": rpCallback, "scope": "openid"}))
			r := b.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true})
			code, _ := codeFrom(t, r.JSON()["redirectURI"].(string))
			bad := e.token(e.srv.Browser(), url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}}, basic(cl.ID, "wrong"))
			expectOAuthError(t, bad, 401, "invalid_client", "invalid client_secret")
			b.Get(e.authorizeURL(map[string]string{"response_type": "code", "client_id": cl.ID, "redirect_uri": rpCallback, "scope": "openid", "prompt": "consent"}))
			r = b.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true})
			code, _ = codeFrom(t, r.JSON()["redirectURI"].(string))
			ok := e.token(e.srv.Browser(), url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}}, basic(cl.ID, cl.Secret))
			if ok.Status != http.StatusOK {
				t.Fatalf("token: %s", ok)
			}
			// better-auth signs the HS256 id_token with the secret as stored
			if _, err := jwt.Parse(ok.JSON()["id_token"].(string), func(*jwt.Token) (any, error) { return []byte(rec["clientSecret"].(string)), nil }); err != nil {
				t.Fatalf("id_token with stored secret: %v", err)
			}
		})
	}
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func TestEndSession(t *testing.T) {
	c := newCodeEnv(t, oidcconfig.Config{})
	path := func(q url.Values) string { return c.srv.Path("/oauth2/endsession") + "?" + q.Encode() }
	anon := c.srv.Browser()
	// Step 1: client checks
	expectOAuthError(t, anon.Get(path(url.Values{"client_id": {"ghost"}})), 400, "invalid_client", "Invalid client_id")
	expectOAuthError(t, anon.Get(path(url.Values{"post_logout_redirect_uri": {rpCallback}})), 400, "invalid_request", "client_id is required when using post_logout_redirect_uri without a valid id_token_hint")
	expectOAuthError(t, anon.Get(path(url.Values{"client_id": {trusted.ClientID}, "post_logout_redirect_uri": {"https://evil.example.com"}})), 400, "invalid_request", "post_logout_redirect_uri is not registered for this client")
	// Step 2: an id_token for another client
	tok := c.exchange(c.code(nil), nil).JSON()
	idToken := tok["id_token"].(string)
	expectOAuthError(t, anon.Get(path(url.Values{"client_id": {trusted.ClientID}, "id_token_hint": {forgeAud(t, idToken, "other-client")}})), 400, "invalid_request", "client_id does not match the ID Token's audience")
	// Step 3: without a session, a valid hint revokes the user's tokens; JSON answer without a redirect
	r := anon.Get(path(url.Values{"client_id": {trusted.ClientID}, "id_token_hint": {idToken}}))
	if r.Status != 200 || r.JSON()["success"] != true || r.JSON()["message"] != "Logout successful" {
		t.Fatalf("endsession json: %s", r)
	}
	expectOAuthError(t, anon.Get(c.srv.Path("/oauth2/userinfo"), map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)}), 401, "invalid_token", "invalid access token")
	// the user's session is untouched (no cookie on the request)
	if r := c.user.Get("/api/auth/get-session"); !strings.Contains(string(r.Body), c.userID) {
		t.Fatalf("session must survive: %s", r)
	}
	// Step 4: POST works the same (parameters in the query), with the session: it is ended
	r = c.user.Post(path(url.Values{"client_id": {trusted.ClientID}, "post_logout_redirect_uri": {"https://rp.example.com/other"}}), nil)
	if r.Status != http.StatusFound || r.Header.Get("Location") != "https://rp.example.com/other" {
		t.Fatalf("endsession POST: %s", r)
	}
	if r := c.user.Get("/api/auth/get-session"); strings.TrimSpace(string(r.Body)) != "null" {
		t.Fatalf("session must be gone: %s", r)
	}
}

// forgeAud re-signs an HS256 id_token with another audience (same key).
func forgeAud(t *testing.T, token, aud string) string {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return []byte(trusted.ClientSecret), nil }); err != nil {
		t.Fatal(err)
	}
	claims["aud"] = aud
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(trusted.ClientSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMetadata(t *testing.T) {
	// Step 1: the default document
	e := newEnvWith(t, oidcconfig.Config{Metadata: map[string]any{"service_documentation": "https://docs.example.com", "scopes_supported": []string{"openid"}}},
		func(c *config.AuthConfig) { c.BasePath = "/auth" })
	r := e.srv.Browser().Get(e.srv.URL + "/auth/.well-known/openid-configuration")
	m := r.JSON()
	base := e.srv.URL + "/auth"
	if r.Status != 200 || m["issuer"] != e.srv.URL || m["authorization_endpoint"] != base+"/oauth2/authorize" || m["token_endpoint"] != base+"/oauth2/token" ||
		m["userinfo_endpoint"] != base+"/oauth2/userinfo" || m["jwks_uri"] != base+"/jwks" || m["registration_endpoint"] != base+"/oauth2/register" ||
		m["end_session_endpoint"] != base+"/oauth2/endsession" || strings.Join(toStrings(m["id_token_signing_alg_values_supported"]), ",") != "HS256" ||
		strings.Join(toStrings(m["code_challenge_methods_supported"]), ",") != "S256" ||
		strings.Join(toStrings(m["token_endpoint_auth_methods_supported"]), ",") != "client_secret_basic,client_secret_post,none" {
		t.Fatalf("metadata: %s", r)
	}
	// Step 2: overrides win
	if m["service_documentation"] != "https://docs.example.com" || strings.Join(toStrings(m["scopes_supported"]), ",") != "openid" {
		t.Fatalf("overrides: %v", m)
	}
	// Step 3: MetadataHandler serves the same document anywhere
	e.srv.Mux.Handle("/.well-known/openid-configuration", e.p.MetadataHandler())
	if r2 := e.srv.Browser().Get("/.well-known/openid-configuration"); r2.Status != 200 || r2.JSON()["token_endpoint"] != m["token_endpoint"] {
		t.Fatalf("handler: %s", r2)
	}
}
