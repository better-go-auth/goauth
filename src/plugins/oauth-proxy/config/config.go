// Package config holds the options of the oauth-proxy plugin (better-auth's OAuthProxyOptions).
package config

import "time"

// DefaultMaxAge is how long an encrypted profile handed from production to the preview deployment stays
// valid (better-auth's maxAge default: 60 seconds).
const DefaultMaxAge = 60 * time.Second

// OAuthProxyConfig configures the oauth-proxy plugin.
type OAuthProxyConfig struct {
	// ProductionURL is the URL of the production deployment, the only redirect URI registered at the OAuth
	// providers (e.g. "https://my-app.com"). Preview deployments send the provider's callback there, and
	// production forwards the signed-in profile back to the preview. Default: $BETTER_AUTH_URL, else the
	// app's BaseURL (which makes every deployment skip the proxy).
	ProductionURL string
	// CurrentURL is the URL of the current deployment. Default: the request URL (scheme from
	// X-Forwarded-Proto, else BaseURL's scheme when the host matches, else http), then the vendor variables
	// VERCEL_URL, NETLIFY_URL, RENDER_URL, ... and finally the app's base URL.
	CurrentURL string
	// MaxAge is how long the encrypted profile is accepted by /oauth-proxy-callback (default 60 seconds).
	MaxAge time.Duration
	// Secret encrypts the state package and the profile (default: the auth secret). Production and preview
	// deployments must share it.
	Secret string
}

// WithDefaults fills unset options with better-auth's defaults.
func (c OAuthProxyConfig) WithDefaults() OAuthProxyConfig {
	if c.MaxAge <= 0 {
		c.MaxAge = DefaultMaxAge
	}
	return c
}
