package test

import (
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	genericoauth "github.com/better-go-auth/goauth/src/plugins/generic-oauth"
	goconfig "github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	"github.com/better-go-auth/goauth/src/plugins/scim"
	scimconfig "github.com/better-go-auth/goauth/src/plugins/scim/config"
	"github.com/better-go-auth/goauth/src/plugins/sso"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// TestInstalledWithOtherPlugins mounts sso and scim next to plugins with similar endpoints and response types
// (Huma schema names and routes must not collide) and checks both answer.
func TestInstalledWithOtherPlugins(t *testing.T) {
	s := compattest.NewServer(t,
		compattest.WithPlugin(sso.New(ssoconfig.SSOConfig{DomainVerification: ssoconfig.DomainVerification{Enabled: true}})),
		compattest.WithPlugin(scim.New(scimconfig.SCIMConfig{ProviderOwnership: true})),
		compattest.WithPlugin(emailotp.New(emailotpconfig.EmailOTPConfig{})),
		compattest.WithPlugin(username.New(usernameconfig.UsernameConfig{})),
		compattest.WithPlugin(genericoauth.New(goconfig.Config{Providers: []goconfig.ProviderConfig{{
			ProviderID: "gen", AuthorizationURL: "https://idp.example/auth", TokenURL: "https://idp.example/token", ClientID: "c", ClientSecret: "s",
		}}})),
		compattest.WithConfig(func(c *config.AuthConfig) { c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*") }),
	)
	// generic-oauth's provider id is a social provider id: reserved for SSO
	r := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "combo@x.com", "password": "password1234", "name": "Combo"})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up %d %s", r.Status, r.Body)
	}
	r = s.Post(t, "/api/auth/sso/register", map[string]any{"providerId": "gen", "issuer": "https://idp.example", "domain": "x.com", "oidcConfig": map[string]any{"clientId": "c", "clientSecret": "s"}})
	expectError(t, r, http.StatusUnprocessableEntity, "", "This providerId is reserved and cannot be used for an SSO provider")
	if r := s.Get(t, "/api/auth/scim/v2/ServiceProviderConfig"); r.Status != http.StatusOK {
		t.Fatalf("scim metadata %d", r.Status)
	}
}
