// Package config holds the options of the mcp plugin (better-auth's MCPOptions).
package config

import (
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
)

// Config holds better-auth's MCPOptions.
type Config struct {
	// LoginPage is where users without a session are sent by /mcp/authorize. Required.
	LoginPage string
	// Resource is the protected resource identifier of /.well-known/oauth-protected-resource (default: the
	// origin of the base URL).
	Resource string
	// OIDCConfig configures the underlying OAuth provider (token lifetimes, scopes, PKCE, consent page,
	// client ID/secret generators, additional claims, ...). Its LoginPage is replaced by LoginPage.
	OIDCConfig oidcconfig.Config
}

// ProviderConfig returns the oidc-provider configuration the mcp plugin runs with (better-auth's opts:
// the OIDC defaults, OIDCConfig, LoginPage).
func (c Config) ProviderConfig() oidcconfig.Config {
	pc := c.OIDCConfig
	pc.LoginPage = c.LoginPage
	return pc.WithDefaults()
}
