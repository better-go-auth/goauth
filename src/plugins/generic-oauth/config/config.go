// Package config holds the generic-oauth plugin options: better-auth's GenericOAuthOptions /
// GenericOAuthConfig plus the `account` options (linking policy, token storage, OAuth state) that goauth keeps
// per plugin instead of in core AuthConfig.
package config

import (
	"context"
	"net/http"
	"time"

	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// GetTokenInput is the argument of ProviderConfig.GetToken (better-auth's getToken data).
type GetTokenInput struct {
	Code        string
	RedirectURI string
	// CodeVerifier is only set when PKCE is enabled for the provider.
	CodeVerifier string
}

// ProviderConfig is better-auth's GenericOAuthConfig: one OAuth 2.0 / OpenID Connect provider.
type ProviderConfig struct {
	// ProviderID is the unique provider id stored on accounts and used in /oauth2/callback/{providerId}.
	ProviderID string
	// DiscoveryURL is the OIDC discovery document (".well-known/openid-configuration"). When set, its
	// endpoints take precedence over AuthorizationURL / TokenURL / UserInfoURL (like better-auth).
	DiscoveryURL string
	// Issuer is the expected authorization server issuer for RFC 9207 `iss` validation (defaults to the
	// discovery document's issuer).
	Issuer string
	// RequireIssuerValidation rejects callbacks without an `iss` parameter when an issuer is known.
	RequireIssuerValidation bool
	// AuthorizationURL, TokenURL and UserInfoURL are the provider endpoints (or use DiscoveryURL).
	AuthorizationURL string
	TokenURL         string
	UserInfoURL      string
	// ClientID / ClientSecret are the OAuth client credentials.
	ClientID     string
	ClientSecret string
	// Scopes are requested on every authorization.
	Scopes []string
	// RedirectURI overrides "<baseURL>/oauth2/callback/<providerId>".
	RedirectURI string
	// ResponseType overrides response_type (default "code").
	ResponseType string
	// ResponseMode sets response_mode ("query" or "form_post").
	ResponseMode string
	// Prompt sets the prompt parameter ("none", "login", "consent", "select_account", ...).
	Prompt string
	// PKCE sends an S256 code_challenge and the code_verifier.
	PKCE bool
	// AccessType sets access_type (e.g. "offline").
	AccessType string
	// AccessTokenExpiresIn is the default access token lifetime when the token response has no expires_in.
	AccessTokenExpiresIn time.Duration
	// GetToken replaces the authorization code exchange.
	GetToken func(ctx context.Context, in GetTokenInput) (*providers.OAuth2Tokens, error)
	// GetUserInfo replaces the user info lookup. It returns the profile as a map with the keys "id", "name",
	// "email", "image" and "emailVerified" (plus anything else); nil means the user could not be resolved.
	GetUserInfo func(ctx context.Context, tokens providers.OAuth2Tokens) (map[string]any, error)
	// MapProfileToUser maps the profile to user fields. Its keys override the profile ("id", "name",
	// "email", "image", "emailVerified"); other keys (e.g. "firstName", "username") are copied onto new users.
	MapProfileToUser func(profile map[string]any) map[string]any
	// AuthorizationURLParams are extra authorization URL parameters.
	AuthorizationURLParams map[string]string
	// AuthorizationURLParamsFunc computes extra authorization URL parameters per request (better-auth's
	// function form of authorizationUrlParams). Its values win over AuthorizationURLParams.
	AuthorizationURLParamsFunc func(ctx context.Context) map[string]string
	// TokenURLParams are extra token request parameters (they never override the standard ones).
	TokenURLParams map[string]string
	// TokenURLParamsFunc computes extra token request parameters per request (function form of tokenUrlParams).
	TokenURLParamsFunc func(ctx context.Context) map[string]string
	// DisableImplicitSignUp only creates users when the sign-in request sets requestSignUp.
	DisableImplicitSignUp bool
	// DisableSignUp never creates users through this provider.
	DisableSignUp bool
	// Authentication of the token endpoint: providers.AuthPost (default) or providers.AuthBasic.
	Authentication providers.TokenAuth
	// DiscoveryHeaders are sent with the discovery request.
	DiscoveryHeaders map[string]string
	// AuthorizationHeaders are sent with the token request.
	AuthorizationHeaders map[string]string
	// OverrideUserInfo updates the local user with the provider profile on every sign-in.
	OverrideUserInfo bool
	// HTTPClient is used for discovery, token and user info requests (default: 10s timeout).
	HTTPClient *http.Client
}

// Config configures the generic-oauth plugin.
type Config struct {
	// Providers are the configured OAuth providers (better-auth's `config` array).
	Providers []ProviderConfig

	// AccountLinking is the account linking policy (better-auth's account.accountLinking).
	AccountLinking socialconfig.AccountLinking
	// EncryptOAuthTokens stores access/refresh tokens encrypted with the auth secret.
	EncryptOAuthTokens bool
	// UpdateAccountOnSignIn refreshes the stored tokens on every sign-in (default true).
	UpdateAccountOnSignIn *bool
	// StoreStateStrategy is socialconfig.StateDatabase (default) or socialconfig.StateCookie.
	StoreStateStrategy socialconfig.StateStrategy
	// SkipStateCookieCheck skips the signed `state` cookie check of the database strategy.
	SkipStateCookieCheck bool
	// ErrorURL is better-auth's onAPIError.errorURL (default "<baseURL><basePath>/error").
	ErrorURL string
	// DiscoveryCacheTTL caches successful discovery documents (default 10 minutes, negative disables).
	DiscoveryCacheTTL time.Duration
}

// DefaultDiscoveryCacheTTL is the default lifetime of a cached discovery document.
const DefaultDiscoveryCacheTTL = 10 * time.Minute

// CacheTTL returns the effective discovery cache lifetime (0 = no cache).
func (c Config) CacheTTL() time.Duration {
	switch {
	case c.DiscoveryCacheTTL < 0:
		return 0
	case c.DiscoveryCacheTTL == 0:
		return DefaultDiscoveryCacheTTL
	default:
		return c.DiscoveryCacheTTL
	}
}

// SocialConfig returns the shared OAuth options in the social plugin's format (without providers).
func (c Config) SocialConfig() socialconfig.SocialConfig {
	return socialconfig.SocialConfig{
		AccountLinking:        c.AccountLinking,
		EncryptOAuthTokens:    c.EncryptOAuthTokens,
		UpdateAccountOnSignIn: c.UpdateAccountOnSignIn,
		StoreStateStrategy:    c.StoreStateStrategy,
		SkipStateCookieCheck:  c.SkipStateCookieCheck,
		ErrorURL:              c.ErrorURL,
	}
}
