package test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/oidctest"
)

// hmacKeySet verifies HS256 id_tokens with the client secret (go-oidc only ships asymmetric key sets).
type hmacKeySet struct{ secret []byte }

func (k hmacKeySet) VerifySignature(_ context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		return nil, err
	}
	return jws.Verify(k.secret)
}

// rpFlow runs the authorization code flow as a golang.org/x/oauth2 relying party against the provider
// discovered by go-oidc: the user's browser authorizes (login page → sign-in resumes the request), the
// RP exchanges the code with PKCE and gets the id_token.
func rpFlow(t *testing.T, e *env, provider *oidc.Provider, cfg oauth2.Config, user *oidctest.Browser, email string) (*oauth2.Token, string) {
	t.Helper()
	// Step 1: the RP's authorization URL (state, nonce, PKCE S256)
	verifier := oauth2.GenerateVerifier()
	authURL := cfg.AuthCodeURL("rp-state", oidc.Nonce("rp-nonce"), oauth2.S256ChallengeOption(verifier))
	if !strings.HasPrefix(authURL, e.srv.Path("/oauth2/authorize")) {
		t.Fatalf("auth URL %s", authURL)
	}
	// Step 2: the browser: login page, then sign-in resumes the authorization
	r := user.Get(authURL)
	if r.Status != http.StatusFound || !strings.HasPrefix(r.Header.Get("Location"), loginPage) {
		t.Fatalf("authorize: %s", r)
	}
	r = user.SignIn(email)
	code, state := codeFrom(t, r.Header.Get("Location"))
	if state != "rp-state" {
		t.Fatalf("state %q", state)
	}
	// Step 3: the RP exchanges the code
	tok, err := cfg.Exchange(context.Background(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		t.Fatalf("no id_token in %+v", tok)
	}
	return tok, raw
}

// TestGoOIDCRelyingPartyHS256 validates the HS256 id_token (client secret) with go-oidc.
func TestGoOIDCRelyingPartyHS256(t *testing.T) {
	e := newEnv(t, oidcconfig.Config{TrustedClients: []oidcconfig.Client{trusted}})
	// Step 1: discovery at the issuer (MetadataHandler mounted at the origin)
	e.srv.Mux.Handle("/.well-known/openid-configuration", e.p.MetadataHandler())
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, e.srv.URL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	cfg := oauth2.Config{ClientID: trusted.ClientID, ClientSecret: trusted.ClientSecret, Endpoint: provider.Endpoint(),
		RedirectURL: rpCallback, Scopes: []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess}}
	user := e.srv.Browser()
	userID := user.SignUp("rp@example.com", "Relying Party")
	user = e.srv.Browser()
	tok, raw := rpFlow(t, e, provider, cfg, user, "rp@example.com")

	// Step 2: verify the id_token (better-auth's HS256 token has no iss claim, so the issuer check is skipped)
	verifier := oidc.NewVerifier(e.srv.URL, hmacKeySet{secret: []byte(trusted.ClientSecret)},
		&oidc.Config{ClientID: trusted.ClientID, SupportedSigningAlgs: []string{"HS256"}, SkipIssuerCheck: true})
	idt, err := verifier.Verify(ctx, raw)
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
	}
	if err := idt.Claims(&claims); err != nil || idt.Subject != userID || idt.Nonce != "rp-nonce" || claims.Email != "rp@example.com" || claims.GivenName != "Relying" {
		t.Fatalf("id_token: %+v %+v %v", idt, claims, err)
	}
	if time.Until(idt.Expiry) < 55*time.Minute {
		t.Fatalf("expiry %v", idt.Expiry)
	}
	// a wrong secret fails
	bad := oidc.NewVerifier(e.srv.URL, hmacKeySet{secret: []byte("wrong")}, &oidc.Config{ClientID: trusted.ClientID, SupportedSigningAlgs: []string{"HS256"}, SkipIssuerCheck: true})
	if _, err := bad.Verify(ctx, raw); err == nil {
		t.Fatal("wrong secret verified")
	}

	// Step 3: userinfo through go-oidc
	ui, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil || ui.Subject != userID || ui.Email != "rp@example.com" {
		t.Fatalf("userinfo: %+v %v", ui, err)
	}
	// Step 4: refresh through x/oauth2
	expired := &oauth2.Token{RefreshToken: tok.RefreshToken, Expiry: time.Now().Add(-time.Hour)}
	next, err := cfg.TokenSource(ctx, expired).Token()
	if err != nil || next.AccessToken == "" || next.AccessToken == tok.AccessToken {
		t.Fatalf("refresh: %+v %v", next, err)
	}
	// Step 5: x/oauth2 surfaces the RFC 6749 error of a bad exchange
	_, err = cfg.Exchange(ctx, "bad-code")
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) || re.ErrorCode != "invalid_grant" || re.ErrorDescription != "invalid code" {
		t.Fatalf("bad code: %v", err)
	}
}

// TestGoOIDCRelyingPartyJWTPlugin validates jwt-plugin id_tokens with go-oidc through the JWKS (RS256 and
// the jwt plugin's default EdDSA), with a confidential and a public (PKCE only) client.
func TestGoOIDCRelyingPartyJWTPlugin(t *testing.T) {
	for _, alg := range []string{jwtconfig.AlgRS256, jwtconfig.AlgEdDSA} {
		t.Run(alg, func(t *testing.T) {
			jp := jwt.New(jwtconfig.JWTConfig{Jwks: jwtconfig.JwksConfig{KeyPairConfig: jwtconfig.KeyPairConfig{Alg: alg}}})
			e := newEnv(t, oidcconfig.Config{UseJWTPlugin: true, TrustedClients: []oidcconfig.Client{trusted, publicClient}}, jp)
			e.srv.Mux.Handle("/.well-known/openid-configuration", e.p.MetadataHandler())
			ctx := context.Background()
			// Step 1: discovery advertises RS256/EdDSA and the JWKS
			provider, err := oidc.NewProvider(ctx, e.srv.URL)
			if err != nil {
				t.Fatalf("discovery: %v", err)
			}
			var md struct {
				Algs []string `json:"id_token_signing_alg_values_supported"`
				JWKS string   `json:"jwks_uri"`
			}
			_ = provider.Claims(&md)
			if strings.Join(md.Algs, ",") != "RS256,EdDSA" || md.JWKS != e.srv.Path("/jwks") {
				t.Fatalf("metadata %+v", md)
			}
			verifier := provider.Verifier(&oidc.Config{ClientID: trusted.ClientID, SupportedSigningAlgs: []string{alg}})
			// Step 2: confidential client, full verification (issuer, audience, signature through the JWKS)
			cfg := oauth2.Config{ClientID: trusted.ClientID, ClientSecret: trusted.ClientSecret, Endpoint: provider.Endpoint(),
				RedirectURL: rpCallback, Scopes: []string{oidc.ScopeOpenID, "email"}}
			user := e.srv.Browser()
			userID := user.SignUp("jwt@example.com", "Jay Wt")
			user = e.srv.Browser()
			_, raw := rpFlow(t, e, provider, cfg, user, "jwt@example.com")
			idt, err := verifier.Verify(ctx, raw)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			var claims map[string]any
			_ = idt.Claims(&claims)
			if idt.Issuer != e.srv.URL || idt.Subject != userID || idt.Nonce != "rp-nonce" || claims["email"] != "jwt@example.com" {
				t.Fatalf("claims: %+v %v", idt, claims)
			}
			// Step 3: a public client gets a verifiable id_token too (no client secret needed)
			pcfg := oauth2.Config{ClientID: publicClient.ClientID, Endpoint: provider.Endpoint(), RedirectURL: "myapp://callback", Scopes: []string{oidc.ScopeOpenID}}
			verifierPKCE := oauth2.GenerateVerifier()
			r := user.Get(pcfg.AuthCodeURL("p", oauth2.S256ChallengeOption(verifierPKCE)))
			code, _ := codeFrom(t, r.Header.Get("Location"))
			ptok, err := pcfg.Exchange(ctx, code, oauth2.VerifierOption(verifierPKCE))
			if err != nil {
				t.Fatalf("public exchange: %v", err)
			}
			if _, err := provider.Verifier(&oidc.Config{ClientID: publicClient.ClientID, SupportedSigningAlgs: []string{alg}}).Verify(ctx, ptok.Extra("id_token").(string)); err != nil {
				t.Fatalf("public id_token: %v", err)
			}
			// Step 4: better-auth verifies a jwt-plugin id_token_hint against the jwt audience (the base URL),
			// which an id_token (aud = client) never matches: the hint is ignored, client_id is needed
			r = user.Get(e.srv.Path("/oauth2/endsession") + "?" + url.Values{"id_token_hint": {raw}, "post_logout_redirect_uri": {rpCallback}}.Encode())
			expectOAuthError(t, r, 400, "invalid_request", "client_id is required when using post_logout_redirect_uri without a valid id_token_hint")
		})
	}
}

// TestJWTIssuerInMetadata: the jwt plugin's issuer is the discovery issuer.
func TestJWTIssuerInMetadata(t *testing.T) {
	jp := jwt.New(jwtconfig.JWTConfig{JWT: jwtconfig.JWTClaimConfig{Issuer: "https://issuer.example.com"}})
	e := newEnv(t, oidcconfig.Config{}, jp)
	r := e.srv.Browser().Get(e.srv.Path("/.well-known/openid-configuration"))
	if r.JSON()["issuer"] != "https://issuer.example.com" {
		t.Fatalf("issuer: %s", r)
	}
}
