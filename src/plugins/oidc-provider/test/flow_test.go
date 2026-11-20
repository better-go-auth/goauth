package test

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
	"github.com/golang-jwt/jwt/v5"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// TestAuthorizationCodeFlow walks the whole browser flow: authorize without a session → login page →
// sign-in resumes the request (after hook) → consent page → consent → code → token (PKCE + basic auth)
// → id_token → userinfo → reused code → refresh → second authorization without consent → end session.
func TestAuthorizationCodeFlow(t *testing.T) {
	e := newEnv(t, oidcconfig.Config{ConsentPage: consentPage})
	// Step 1: a developer registers a client
	dev := e.srv.Browser()
	dev.SignUp("dev@example.com", "Dev Eloper")
	c := e.register(dev)
	// Step 2: the user exists but is signed out
	u := e.srv.Browser()
	userID := u.SignUp("alice@example.com", "Alice Liddell")
	u = e.srv.Browser()

	// Step 3: authorize without a session → login page with the original query, flow cookie set
	verifier, challenge := pkce()
	authURL := e.authorizeURL(map[string]string{
		"response_type": "code", "client_id": c.ID, "redirect_uri": rpCallback, "scope": "openid profile email offline_access",
		"state": "st-1", "nonce": "n-1", "code_challenge": challenge, "code_challenge_method": "S256",
	})
	r := u.Get(authURL)
	if r.Status != http.StatusFound || !strings.HasPrefix(r.Header.Get("Location"), loginPage+"?") {
		t.Fatalf("authorize without session: %s", r)
	}
	if got := strings.TrimPrefix(r.Header.Get("Location"), loginPage+"?"); got != strings.SplitN(authURL, "?", 2)[1] {
		t.Fatalf("login page query = %q", got)
	}
	ck := r.Cookie(services.LoginPromptCookie)
	if ck == nil || ck.MaxAge != 600 || ck.Path != "/" || ck.HttpOnly {
		t.Fatalf("oidc_login_prompt cookie = %+v", ck)
	}

	// Step 4: signing in resumes the request: the consent page, with the session and consent cookies
	r = u.SignIn("alice@example.com")
	loc := r.Location()
	if r.Status != http.StatusFound || loc == nil || loc.Path != consentPage {
		t.Fatalf("sign-in did not resume the authorization: %s", r)
	}
	if loc.Query().Get("client_id") != c.ID || loc.Query().Get("scope") != "openid profile email offline_access" || loc.Query().Get("consent_code") == "" {
		t.Fatalf("consent page query = %v", loc.Query())
	}
	if r.Cookie("better-auth.session_token") == nil || r.Cookie(services.ConsentPromptCookie) == nil {
		t.Fatalf("sign-in cookies: %v", r.Header.Values("Set-Cookie"))
	}
	if lp := r.Cookie(services.LoginPromptCookie); lp == nil || lp.MaxAge >= 0 {
		t.Fatalf("oidc_login_prompt must be expired: %+v", lp)
	}

	// Step 5: the public client info for the consent screen
	r = u.Get(e.srv.Path("/oauth2/client/" + c.ID))
	if r.Status != http.StatusOK || r.JSON()["name"] != "RP App" || r.JSON()["clientId"] != c.ID {
		t.Fatalf("client info: %s", r)
	}

	// Step 6: consent (cookie flow) → redirect URI with code and state
	r = u.Post(e.srv.Path("/oauth2/consent"), map[string]any{"accept": true})
	if r.Status != http.StatusOK {
		t.Fatalf("consent: %s", r)
	}
	code, state := codeFrom(t, r.JSON()["redirectURI"].(string))
	if state != "st-1" || code == "" || !strings.HasPrefix(r.JSON()["redirectURI"].(string), rpCallback+"?code=") {
		t.Fatalf("consent redirect = %v", r.JSON())
	}

	// Step 7: the RP exchanges the code (client_secret_basic + PKCE)
	rp := e.srv.Browser()
	r = e.token(rp, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {verifier}}, basic(c.ID, c.Secret))
	if r.Status != http.StatusOK || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("token: %s", r)
	}
	tok := r.JSON()
	if tok["token_type"] != "Bearer" || tok["expires_in"] != float64(3600) || tok["scope"] != "openid profile email offline_access" ||
		tok["refresh_token"] == nil || tok["id_token"] == nil {
		t.Fatalf("token body = %v", tok)
	}

	// Step 8: the id_token is HS256 with the client secret
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(tok["id_token"].(string), claims, func(*jwt.Token) (any, error) { return []byte(c.Secret), nil },
		jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("id_token: %v", err)
	}
	if claims["sub"] != userID || claims["aud"] != c.ID || claims["nonce"] != "n-1" || claims["email"] != "alice@example.com" ||
		claims["given_name"] != "Alice" || claims["family_name"] != "Liddell" || claims["name"] != "Alice Liddell" ||
		claims["acr"] != "urn:mace:incommon:iap:silver" || claims["email_verified"] != false {
		t.Fatalf("id_token claims = %v", claims)
	}
	if _, ok := claims["iss"]; ok {
		t.Fatalf("better-auth's HS256 id_token has no iss: %v", claims)
	}
	if _, ok := parsed.Header["typ"]; ok || parsed.Header["alg"] != "HS256" {
		t.Fatalf("header = %v", parsed.Header)
	}

	// Step 9: userinfo
	r = rp.Get(e.srv.Path("/oauth2/userinfo"), map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)})
	ui := r.JSON()
	if r.Status != http.StatusOK || ui["sub"] != userID || ui["email"] != "alice@example.com" || ui["name"] != "Alice Liddell" ||
		ui["given_name"] != "Alice" || ui["family_name"] != "Liddell" || ui["email_verified"] != false {
		t.Fatalf("userinfo: %s", r)
	}
	if v, ok := ui["picture"]; !ok || v != nil {
		t.Fatalf("picture must be null: %v", ui)
	}

	// Step 10: a code works once
	r = e.token(rp, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {verifier}}, basic(c.ID, c.Secret))
	expectOAuthError(t, r, http.StatusUnauthorized, "invalid_grant", "invalid code")

	// Step 11: refresh (client_secret_post) → a new pair with the same scopes
	r = e.token(rp, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {c.ID}, "client_secret": {c.Secret}})
	ref := r.JSON()
	if r.Status != http.StatusOK || ref["access_token"] == tok["access_token"] || ref["refresh_token"] == nil ||
		ref["scope"] != "openid profile email offline_access" || ref["token_type"] != "Bearer" || ref["id_token"] != nil {
		t.Fatalf("refresh: %s", r)
	}
	if r2 := rp.Get(e.srv.Path("/oauth2/userinfo"), map[string]string{"Authorization": "Bearer " + ref["access_token"].(string)}); r2.Status != http.StatusOK {
		t.Fatalf("userinfo with refreshed token: %s", r2)
	}

	// Step 12: consent is remembered: the next authorization goes straight to the client
	r = u.Get(e.authorizeURL(map[string]string{"response_type": "code", "client_id": c.ID, "redirect_uri": rpCallback, "scope": "openid email", "state": "st-2"}))
	if r.Status != http.StatusFound {
		t.Fatalf("second authorize: %s", r)
	}
	code2, state2 := codeFrom(t, r.Header.Get("Location"))
	if state2 != "st-2" || code2 == "" {
		t.Fatalf("second authorize location %s", r.Header.Get("Location"))
	}

	// Step 13: RP-initiated logout with id_token_hint → redirect with state, tokens revoked, session gone
	r = u.Get(e.srv.Path("/oauth2/endsession") + "?" + url.Values{
		"id_token_hint": {tok["id_token"].(string)}, "client_id": {c.ID}, "post_logout_redirect_uri": {rpCallback}, "state": {"bye"},
	}.Encode())
	if r.Status != http.StatusFound || r.Header.Get("Location") != rpCallback+"?state=bye" {
		t.Fatalf("endsession: %s", r)
	}
	if sc := r.Cookie("better-auth.session_token"); sc == nil || sc.MaxAge >= 0 {
		t.Fatalf("session cookie not expired: %v", r.Header.Values("Set-Cookie"))
	}
	r = rp.Get(e.srv.Path("/oauth2/userinfo"), map[string]string{"Authorization": "Bearer " + ref["access_token"].(string)})
	expectOAuthError(t, r, http.StatusUnauthorized, "invalid_token", "invalid access token")
	if r := u.Get("/api/auth/get-session"); strings.TrimSpace(string(r.Body)) != "null" {
		t.Fatalf("session still alive: %s", r)
	}
}
