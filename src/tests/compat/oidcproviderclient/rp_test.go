package oidcproviderclient

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	plugin "github.com/better-go-auth/goauth/src/plugins"
	genericoauth "github.com/better-go-auth/goauth/src/plugins/generic-oauth"
	goconfig "github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	"github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	oidcprovider "github.com/better-go-auth/goauth/src/plugins/oidc-provider"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/oidctest"
	socialproviders "github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// TestGoAuthAsIdPForGoAuthRP signs in to a goauth application (the relying party, generic-oauth plugin with
// OIDC discovery) with a goauth identity provider (oidc-provider plugin): RP sign-in → IdP authorize →
// IdP login page → IdP sign-in resumes the request → consent (first time) → RP callback → the RP
// exchanges the code, reads the user and starts its own session.
func TestGoAuthAsIdPForGoAuthRP(t *testing.T) {
	cases := []struct {
		name    string
		jwt     bool
		auth    socialproviders.TokenAuth
		consent bool
	}{
		{name: "hs256-basic-consent", auth: socialproviders.AuthBasic, consent: true},
		{name: "jwt-post-trusted", jwt: true, auth: socialproviders.AuthPost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: the RP's address first: the IdP's client needs its callback URL
			rpListener := oidctest.Listen(t)
			rpCallback := oidctest.URL(rpListener) + "/api/auth/oauth2/callback/goauth-idp"
			// Step 2: the IdP with the RP as a trusted client (consent screen unless SkipConsent)
			var idpPlugins []plugin.Plugin
			if tc.jwt {
				idpPlugins = append(idpPlugins, jwt.New(jwtconfig.JWTConfig{Jwks: jwtconfig.JwksConfig{KeyPairConfig: jwtconfig.KeyPairConfig{Alg: jwtconfig.AlgRS256}}}))
			}
			client := oidcconfig.Client{ClientID: "rp-app", ClientSecret: "rp-secret-0123456789abcdef0123456789", Type: oidcconfig.ClientTypeWeb,
				Name: "RP App", SkipConsent: !tc.consent, RedirectURLs: []string{rpCallback}}
			idp := oidctest.NewServer(t, oidctest.Options{Plugins: append(idpPlugins, oidcprovider.New(oidcconfig.Config{
				LoginPage: "/login", ConsentPage: "/consent", UseJWTPlugin: tc.jwt, TrustedClients: []oidcconfig.Client{client},
			}))})
			// Step 2b: the RP points generic-oauth at the IdP's discovery document
			rp := oidctest.NewServer(t, oidctest.Options{Listener: rpListener, Plugins: []plugin.Plugin{genericoauth.New(goconfig.Config{Providers: []goconfig.ProviderConfig{{
				ProviderID: "goauth-idp", DiscoveryURL: idp.Path("/.well-known/openid-configuration"),
				ClientID: client.ClientID, ClientSecret: client.ClientSecret, Scopes: []string{"openid", "email", "profile"},
				PKCE: true, Authentication: tc.auth,
			}}})}})

			// Step 3: the user exists at the IdP only
			idpBrowser := idp.Browser()
			idpUserID := idpBrowser.SignUp("idp.user@example.com", "Idp User")
			idpBrowser = idp.Browser()

			// Step 4: the RP starts the sign-in
			rpBrowser := rp.Browser()
			r := rpBrowser.Post("/api/auth/sign-in/oauth2", map[string]any{"providerId": "goauth-idp", "callbackURL": "/dashboard"})
			authURL, _ := r.JSON()["url"].(string)
			if r.Status != http.StatusOK || !strings.HasPrefix(authURL, idp.Path("/oauth2/authorize")) {
				t.Fatalf("rp sign-in: %s", r)
			}
			// Step 5: the IdP: login page, sign-in resumes, consent when needed
			r = idpBrowser.Get(authURL)
			if r.Status != http.StatusFound || !strings.HasPrefix(r.Header.Get("Location"), "/login?") {
				t.Fatalf("idp authorize: %s", r)
			}
			r = idpBrowser.SignIn("idp.user@example.com")
			callback := r.Header.Get("Location")
			if tc.consent {
				if !strings.HasPrefix(callback, "/consent?") {
					t.Fatalf("expected consent page: %s", r)
				}
				r = idpBrowser.Post(idp.Path("/oauth2/consent"), map[string]any{"accept": true})
				callback, _ = r.JSON()["redirectURI"].(string)
			}
			if !strings.HasPrefix(callback, rpCallback+"?code=") {
				t.Fatalf("idp did not redirect to the rp: %q", callback)
			}
			// Step 6: the RP callback exchanges the code and signs the user in
			r = rpBrowser.Get(callback)
			if r.Status != http.StatusFound || r.Header.Get("Location") != "/dashboard" {
				t.Fatalf("rp callback: %s", r)
			}
			r = rpBrowser.Get("/api/auth/get-session")
			user, _ := r.JSON()["user"].(map[string]any)
			if user["email"] != "idp.user@example.com" || user["name"] != "Idp User" {
				t.Fatalf("rp session: %s", r)
			}
			// Step 7: the RP account is linked to the IdP subject
			r = rpBrowser.Get("/api/auth/list-accounts")
			if !strings.Contains(string(r.Body), `"providerId":"goauth-idp"`) || !strings.Contains(string(r.Body), idpUserID) {
				t.Fatalf("rp accounts: %s", r)
			}
			// Step 8: a second RP sign-in goes straight through (session at the IdP, consent remembered)
			r = rp.Browser().Post("/api/auth/sign-in/oauth2", map[string]any{"providerId": "goauth-idp", "callbackURL": "/again"})
			r = idpBrowser.Get(r.JSON()["url"].(string))
			if loc, _ := url.Parse(r.Header.Get("Location")); r.Status != http.StatusFound || loc.Query().Get("code") == "" {
				t.Fatalf("second authorize: %s", r)
			}
		})
	}
}
