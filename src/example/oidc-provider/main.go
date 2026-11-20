// Command oidc-provider runs goauth as an OpenID Connect provider: other applications ("relying parties")
// send their users to /api/auth/oauth2/authorize, the users sign in and consent here, and the
// applications get an authorization code, tokens, an id_token and the userinfo claims.
//
//	go run ./src/example/oidc-provider    # http://localhost:8080 (discovery: /.well-known/openid-configuration)
//	go test ./src/example/oidc-provider   # the whole flow end to end
//
// The example has a trusted client "demo-rp" (redirect URI http://localhost:3000/callback) and serves a
// minimal login page (/login) and consent page (/consent).
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/models"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	oidcprovider "github.com/better-go-auth/goauth/src/plugins/oidc-provider"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
)

// Demo client of the example (a confidential web application).
const (
	DemoClientID     = "demo-rp"
	DemoClientSecret = "demo-rp-secret-change-me-0123456789"
	DemoRedirectURI  = "http://localhost:3000/callback"
)

// loginHTML is the login page: it signs in with goauth's /sign-in/email. When the request came from
// /oauth2/authorize, the oidc-provider's after hook answers the sign-in with {redirect, url} and the page
// follows it (to the consent page or back to the application).
const loginHTML = `<!doctype html><title>Sign in</title>
<form id="f"><input name="email" placeholder="email"> <input name="password" type="password" placeholder="password"> <button>Sign in</button></form>
<script>
f.onsubmit = async (e) => {
  e.preventDefault();
  const res = await fetch("/api/auth/sign-in/email", {method: "POST", headers: {"content-type": "application/json"},
    body: JSON.stringify({email: f.email.value, password: f.password.value})});
  const data = await res.json();
  if (data.redirect && data.url) location.href = data.url; else document.body.append(JSON.stringify(data));
};
</script>`

// consentHTML is the consent page: /oauth2/consent turns the consent code (signed cookie) into an
// authorization code and returns the client's redirect URI.
const consentHTML = `<!doctype html><title>Consent</title>
<p>An application asks for: <b id="s"></b></p><button id="yes">Allow</button> <button id="no">Deny</button>
<script>
const q = new URLSearchParams(location.search); s.textContent = q.get("scope");
const send = async (accept) => {
  const res = await fetch("/api/auth/oauth2/consent", {method: "POST", headers: {"content-type": "application/json"},
    body: JSON.stringify({accept, consent_code: q.get("consent_code")})});
  const data = await res.json(); if (data.redirectURI) location.href = data.redirectURI;
};
yes.onclick = () => send(true); no.onclick = () => send(false);
</script>`

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, *oidcprovider.Plugin, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, nil, err
	}
	// Step 2: configure the provider (login and consent pages, a trusted client, extra claims)
	provider := oidcprovider.New(oidcconfig.Config{
		LoginPage:   "/login",
		ConsentPage: "/consent",
		TrustedClients: []oidcconfig.Client{{
			ClientID: DemoClientID, ClientSecret: DemoClientSecret, Type: oidcconfig.ClientTypeWeb, Name: "Demo RP",
			RedirectURLs: []string{DemoRedirectURI},
		}},
		// registered applications (POST /api/auth/oauth2/register) need a signed-in user
		AllowDynamicClientRegistration: false,
		GetAdditionalUserInfoClaim: func(_ context.Context, u *models.User, scopes []string, _ *oidcconfig.Client) (map[string]any, error) {
			return map[string]any{"locale": "en"}, nil
		},
	})
	// Step 3: set goauth up
	app, err := exkit.New(context.Background(), exkit.Options{DB: db, Plugins: []plugin.Plugin{provider}})
	if err != nil {
		return nil, nil, err
	}
	// Step 4: the pages and the discovery document where OpenID Connect libraries look for it
	app.Mux.HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) { writeHTML(w, loginHTML) })
	app.Mux.HandleFunc("GET /consent", func(w http.ResponseWriter, _ *http.Request) { writeHTML(w, consentHTML) })
	app.Mux.Handle("GET /.well-known/openid-configuration", provider.MetadataHandler())
	return app, provider, nil
}

func writeHTML(w http.ResponseWriter, page string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "oidc_provider_example.db"
	}
	app, _, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
