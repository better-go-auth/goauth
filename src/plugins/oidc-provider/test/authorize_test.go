package test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	oidcprovider "github.com/better-go-auth/goauth/src/plugins/oidc-provider"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/oidctest"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
)

func TestAuthorizeErrors(t *testing.T) {
	c := newCodeEnv(t, oidcconfig.Config{ConsentPage: consentPage})
	errorPage := c.srv.Path("/error")
	base := map[string]string{"response_type": "code", "client_id": trusted.ClientID, "redirect_uri": rpCallback}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == "" {
				delete(m, kv[i])
				continue
			}
			m[kv[i]] = kv[i+1]
		}
		return m
	}

	// Step 1: errors before the redirect_uri is trusted go to the error page
	expectRedirectError(t, c.user.Get(c.authorizeURL(with("client_id", ""))), errorPage, "invalid_client", "client_id is required")
	expectRedirectError(t, c.user.Get(c.authorizeURL(with("response_type", ""))), errorPage, "invalid_request", "response_type is required")
	expectRedirectError(t, c.user.Get(c.authorizeURL(with("client_id", "ghost"))), errorPage, "invalid_client", "client_id is required")
	expectRedirectError(t, c.user.Get(c.authorizeURL(with("client_id", disabledClient.ClientID))), errorPage, "client_disabled", "client is disabled")
	expectRedirectError(t, c.user.Get(c.authorizeURL(with("response_type", "token"))), errorPage, "unsupported_response_type", "unsupported response type")

	// Step 2: an unregistered redirect_uri is an error page, never a redirect
	for _, uri := range []string{"", "https://evil.example.com/cb", rpCallback + "/"} {
		r := c.user.Get(c.authorizeURL(with("redirect_uri", uri)))
		if r.Status != http.StatusBadRequest || string(r.Body) != "{\"message\":\"Invalid redirect URI\"}\n" {
			t.Fatalf("redirect_uri %q: %s", uri, r)
		}
	}

	// Step 3: errors after it go back to the client
	expectRedirectError(t, c.user.Get(c.authorizeURL(with("scope", "openid admin root"))), rpCallback, "invalid_scope", "The following scopes are invalid: admin, root")
	r := c.user.Get(c.authorizeURL(with("prompt", "none login")))
	if r.Status != http.StatusBadRequest || r.JSON()["error"] != "invalid_request" || r.JSON()["error_description"] != "prompt none must only be used alone" ||
		r.JSON()["message"] != "prompt none must only be used alone" {
		t.Fatalf("prompt none login: %s", r)
	}

	// Step 4: prompt=none for a client the user never consented to
	c.register(c.user)
	reg := c.register(c.user)
	r = c.user.Get(c.authorizeURL(map[string]string{"response_type": "code", "client_id": reg.ID, "redirect_uri": rpCallback, "prompt": "none"}))
	expectRedirectError(t, r, rpCallback, "consent_required", "Consent required but prompt is none")

	// Step 5: a browser fetch (Sec-Fetch-Mode: cors) gets {redirect, url} instead of a 302
	r = c.user.Get(c.authorizeURL(with("scope", "bogus")), map[string]string{"Sec-Fetch-Mode": "cors"})
	if r.Status != http.StatusOK || r.JSON()["redirect"] != true || !strings.HasPrefix(r.JSON()["url"].(string), rpCallback+"?error=invalid_scope") {
		t.Fatalf("fetch redirect: %s", r)
	}

	// Step 6: an empty scope parameter means no scopes (not the default scope)
	r = c.user.Get(c.authorizeURL(with("scope", " ")))
	code, _ := codeFrom(t, r.Header.Get("Location"))
	tok := c.exchange(code, nil)
	if tok.Status != http.StatusOK || tok.JSON()["scope"] != "" || tok.JSON()["id_token"] != nil {
		t.Fatalf("empty scope: %s", tok)
	}
	// Step 7: no scope parameter: DefaultScope
	code, state := codeFrom(t, c.user.Get(c.authorizeURL(with())).Header.Get("Location"))
	if tok := c.exchange(code, nil); tok.JSON()["scope"] != "openid" || state != "undefined" {
		t.Fatalf("default scope: %s (state %q)", tok, state)
	}
}

func TestAuthorizeWithoutSession(t *testing.T) {
	c := newCodeEnv(t, oidcconfig.Config{})
	anon := c.srv.Browser()
	q := func(kv ...string) string {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return c.srv.Path("/oauth2/authorize") + "?" + v.Encode()
	}
	// Step 1: prompt=none cannot show a login page: errors are returned to the client or as JSON
	r := anon.Get(q("prompt", "none", "client_id", trusted.ClientID))
	if r.Status != 400 || r.JSON()["error"] != "invalid_request" ||
		r.JSON()["error_description"] != "redirect_uri is required when prompt=none and must be usable to return errors without displaying UI" {
		t.Fatalf("prompt=none without redirect_uri: %s", r)
	}
	r = anon.Get(q("prompt", "none", "redirect_uri", rpCallback))
	if r.Status != 400 || r.JSON()["error"] != "invalid_client" || r.JSON()["error_description"] != "client_id is required" {
		t.Fatalf("prompt=none without client_id: %s", r)
	}
	r = anon.Get(q("prompt", "none", "redirect_uri", rpCallback, "client_id", "ghost"))
	if r.Status != 400 || r.JSON()["error"] != "invalid_client" {
		t.Fatalf("prompt=none unknown client: %s", r)
	}
	r = anon.Get(q("prompt", "none", "redirect_uri", "https://evil.example.com", "client_id", trusted.ClientID))
	if r.Status != 400 || r.JSON()["error_description"] != "redirect_uri is invalid or not registered for this client" {
		t.Fatalf("prompt=none bad redirect: %s", r)
	}
	r = anon.Get(q("prompt", "none", "redirect_uri", rpCallback, "client_id", trusted.ClientID))
	expectRedirectError(t, r, rpCallback, "login_required", "Authentication required but prompt is none")
	if r.Cookie(services.LoginPromptCookie) != nil {
		t.Fatal("prompt=none must not start a login")
	}
	// Step 2: without query the login page gets better-auth's literal "undefined"
	r = anon.Get(c.srv.Path("/oauth2/authorize"))
	if r.Status != http.StatusFound || r.Header.Get("Location") != loginPage+"?undefined" {
		t.Fatalf("no query: %s", r)
	}
	// Step 3: a browser fetch gets JSON
	r = anon.Get(q("client_id", trusted.ClientID), map[string]string{"Sec-Fetch-Mode": "cors"})
	if r.Status != http.StatusOK || r.JSON()["url"] != loginPage+"?client_id="+trusted.ClientID {
		t.Fatalf("fetch to login page: %s", r)
	}
}

func TestPromptLoginAndMaxAge(t *testing.T) {
	c := newCodeEnv(t, oidcconfig.Config{})
	params := map[string]string{"response_type": "code", "client_id": trusted.ClientID, "redirect_uri": rpCallback, "scope": "openid", "state": "xyz", "prompt": "login"}
	// Step 1: prompt=login with a session: back to the login page with client_id, code and state
	r := c.user.Get(c.authorizeURL(params))
	loc := r.Location()
	if r.Status != http.StatusFound || loc.Path != loginPage || loc.Query().Get("client_id") != trusted.ClientID ||
		loc.Query().Get("state") != "xyz" || loc.Query().Get("code") == "" {
		t.Fatalf("prompt=login: %s", r)
	}
	if r.Cookie(services.LoginPromptCookie) == nil || r.Cookie(services.ConsentPromptCookie) == nil {
		t.Fatalf("prompt=login cookies: %v", r.Header.Values("Set-Cookie"))
	}
	// Step 2: logging in again resumes without prompt=login: the client gets a code
	r = c.user.SignIn("user@example.com")
	code, state := codeFrom(t, r.Header.Get("Location"))
	if r.Status != http.StatusFound || state != "xyz" || !strings.HasPrefix(r.Header.Get("Location"), rpCallback) {
		t.Fatalf("resume after prompt=login: %s", r)
	}
	if tok := c.exchange(code, nil); tok.Status != http.StatusOK {
		t.Fatalf("exchange after re-login: %s", tok)
	}
	// Step 3: a browser fetch sign-in gets {redirect, url} (the better-auth client navigates)
	c.user.Get(c.authorizeURL(params))
	r = c.user.SignIn("user@example.com", map[string]string{"Sec-Fetch-Mode": "cors"})
	if r.Status != http.StatusOK || r.JSON()["redirect"] != true || !strings.HasPrefix(r.JSON()["url"].(string), rpCallback+"?code=") ||
		r.Cookie("better-auth.session_token") == nil {
		t.Fatalf("fetch sign-in resume: %s", r)
	}
	// Step 4: max_age=0 means the session is too old
	delete(params, "prompt")
	params["max_age"] = "0"
	r = c.user.Get(c.authorizeURL(params))
	if loc := r.Location(); r.Status != http.StatusFound || loc.Path != loginPage {
		t.Fatalf("max_age=0: %s", r)
	}
	params["max_age"] = "3600"
	r = c.user.Get(c.authorizeURL(params))
	if !strings.HasPrefix(r.Header.Get("Location"), rpCallback+"?code=") {
		t.Fatalf("max_age=3600: %s", r)
	}
	// Step 5: a sign-in without the flow cookie is a normal sign-in
	b := c.srv.Browser()
	if r := b.SignIn("user@example.com"); r.Status != http.StatusOK || r.JSON()["token"] == nil {
		t.Fatalf("plain sign-in: %s", r)
	}
}

// TestScopesOptions: extra supported scopes and a custom default scope.
func TestScopesOptions(t *testing.T) {
	c := newCodeEnv(t, oidcconfig.Config{Scopes: []string{"read:notes"}, DefaultScope: "openid read:notes"})
	// Step 1: the extra scope is accepted
	if tok := c.exchange(c.code(map[string]string{"scope": "openid read:notes"}), nil); tok.JSON()["scope"] != "openid read:notes" {
		t.Fatalf("extra scope: %s", tok)
	}
	// Step 2: without a scope parameter the default scope applies
	q := map[string]string{"response_type": "code", "client_id": trusted.ClientID, "redirect_uri": rpCallback}
	code, _ := codeFrom(t, c.user.Get(c.authorizeURL(q)).Header.Get("Location"))
	if tok := c.exchange(code, nil); tok.JSON()["scope"] != "openid read:notes" {
		t.Fatalf("default scope: %s", tok)
	}
}

// TestSecondaryStorage: codes live in the secondary storage when one is configured.
func TestSecondaryStorage(t *testing.T) {
	p := oidcprovider.New(oidcconfig.Config{LoginPage: loginPage, TrustedClients: []oidcconfig.Client{trusted}})
	srv := oidctest.NewServer(t, oidctest.Options{Plugins: []plugins.Plugin{p}, SecondaryStorage: true})
	c := &codeEnv{env: &env{t: t, srv: srv, p: p}, user: srv.Browser()}
	c.userID = c.user.SignUp("ss@example.com", "Ss")
	code := c.code(nil)
	if tok := c.exchange(code, nil); tok.Status != 200 {
		t.Fatalf("token: %s", tok)
	}
	expectOAuthError(t, c.exchange(code, nil), 401, "invalid_grant", "invalid code")
}

func TestErrorURLFromOnAPIError(t *testing.T) {
	e := newEnvWith(t, oidcconfig.Config{}, func(c *config.AuthConfig) { c.OnAPIError.ErrorURL = "https://app.example.com/oauth-error?from=idp" })
	b := e.srv.Browser()
	b.SignUp("x@example.com", "X")
	r := b.Get(e.authorizeURL(map[string]string{"response_type": "code"}))
	expectRedirectError(t, r, "https://app.example.com/oauth-error?from=idp&", "invalid_client", "client_id is required")
}

func TestConsent(t *testing.T) {
	e := newEnv(t, oidcconfig.Config{ConsentPage: consentPage})
	b := e.srv.Browser()
	userID := b.SignUp("c@example.com", "Con Sent")
	cl := e.register(b)
	authorize := func(extra ...string) (*url.URL, *http.Cookie) {
		q := map[string]string{"response_type": "code", "client_id": cl.ID, "redirect_uri": rpCallback, "scope": "openid email", "state": "cs"}
		for i := 0; i+1 < len(extra); i += 2 {
			q[extra[i]] = extra[i+1]
		}
		r := b.Get(e.authorizeURL(q))
		return r.Location(), r.Cookie(services.ConsentPromptCookie)
	}

	// Step 1: validation and session come first
	anon := e.srv.Browser()
	if r := anon.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": "yes"}); r.Status != 400 ||
		r.JSON()["message"] != "[body.accept] Invalid input: expected boolean, received string" {
		t.Fatalf("validation: %s", r)
	}
	if r := anon.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true}); r.Status != 401 || r.JSON()["code"] != "UNAUTHORIZED" {
		t.Fatalf("no session: %s", r)
	}
	// Step 2: a consent code is required (body or cookie), and must exist
	fresh := e.srv.Browser()
	fresh.SignIn("c@example.com")
	expectOAuthError(t, fresh.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true}), 401, "invalid_request", "consent_code is required (either in body or cookie)")
	expectOAuthError(t, fresh.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true, "consent_code": "nope"}), 401, "invalid_request", "Invalid code")

	// Step 3: deny → access_denied at the client, the code is gone
	loc, ck := authorize()
	if loc.Path != consentPage || ck == nil {
		t.Fatalf("consent page: %v %v", loc, ck)
	}
	consentCode := loc.Query().Get("consent_code")
	r := b.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": false})
	if r.Status != 200 || r.JSON()["redirectURI"] != rpCallback+"?error=access_denied&error_description=User denied access" {
		t.Fatalf("deny: %s", r)
	}
	expectOAuthError(t, fresh.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true, "consent_code": consentCode}), 401, "invalid_request", "Invalid code")

	// Step 4: an expired consent code
	loc, _ = authorize()
	expireVerification(t, e, loc.Query().Get("consent_code"))
	expectOAuthError(t, fresh.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true, "consent_code": loc.Query().Get("consent_code")}), 401, "invalid_request", "Code expired")

	// Step 5: URL flow (consent_code in the body, from another browser of the same user)
	loc, _ = authorize()
	r = fresh.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true, "consent_code": loc.Query().Get("consent_code")})
	code, state := codeFrom(t, r.JSON()["redirectURI"].(string))
	if r.Status != 200 || state != "cs" || code == "" {
		t.Fatalf("accept: %s", r)
	}
	if r.Cookie(services.ConsentPromptCookie) == nil || r.Cookie(services.ConsentPromptCookie).MaxAge >= 0 {
		t.Fatalf("consent cookie must be expired: %v", r.Header.Values("Set-Cookie"))
	}
	// Step 6: the consent row; the next request with the same (or fewer) scopes skips consent
	var rows []map[string]any
	e.srv.DB.Table("oauthConsent").Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("consent rows = %v", rows)
	}
	loc, _ = authorize("scope", "email")
	if !strings.HasPrefix(loc.String(), rpCallback+"?code=") {
		t.Fatalf("consented scopes: %v", loc)
	}
	// more scopes or prompt=consent ask again
	if loc, _ = authorize("scope", "openid email profile"); loc.Path != consentPage {
		t.Fatalf("new scope must ask: %v", loc)
	}
	if loc, _ = authorize("prompt", "consent"); loc.Path != consentPage {
		t.Fatalf("prompt=consent must ask: %v", loc)
	}
	// Step 7: a code that never needed consent cannot be "consented"
	tc := newCodeEnv(t, oidcconfig.Config{})
	direct := tc.code(nil)
	expectOAuthError(t, tc.user.Post(tc.srv.Path("/oauth2/consent"), map[string]any{"accept": true, "consent_code": direct}), 401, "invalid_request", "Consent not required")
	_ = userID
}

func TestConsentHTML(t *testing.T) {
	// Step 1: GetConsentHTML renders the screen when there is no consent page
	var got oidcconfig.ConsentHTMLProps
	e := newEnv(t, oidcconfig.Config{GetConsentHTML: func(p oidcconfig.ConsentHTMLProps) string {
		got = p
		return "<form>consent " + p.ClientName + "</form>"
	}})
	b := e.srv.Browser()
	b.SignUp("h@example.com", "H")
	cl := e.register(b)
	r := b.Get(e.authorizeURL(map[string]string{"response_type": "code", "client_id": cl.ID, "redirect_uri": rpCallback, "scope": "openid profile"}))
	if r.Status != 200 || r.Header.Get("Content-Type") != "text/html" || string(r.Body) != "<form>consent RP App</form>" {
		t.Fatalf("consent html: %s", r)
	}
	if got.ClientID != cl.ID || got.Code == "" || strings.Join(got.Scopes, " ") != "openid profile" {
		t.Fatalf("props = %+v", got)
	}
	// Step 2: the code of the screen is accepted through the body
	r = b.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true, "consent_code": got.Code})
	if r.Status != 200 {
		t.Fatalf("consent: %s", r)
	}
	// Step 3: neither a page nor HTML → 500 "No consent page provided"
	n := newEnv(t, oidcconfig.Config{})
	nb := n.srv.Browser()
	nb.SignUp("n@example.com", "N")
	ncl := n.register(nb)
	r = nb.Get(n.authorizeURL(map[string]string{"response_type": "code", "client_id": ncl.ID, "redirect_uri": rpCallback}))
	if r.Status != 500 || r.JSON()["message"] != "No consent page provided" {
		t.Fatalf("no consent page: %s", r)
	}
}
