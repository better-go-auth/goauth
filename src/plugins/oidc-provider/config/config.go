// Package config holds the options of the oidc-provider plugin (better-auth's OIDCOptions) and the client
// type shared by the plugin and the mcp plugin.
package config

import (
	"context"
	"time"

	"github.com/better-go-auth/goauth/src/models"
)

// Defaults of better-auth's oidc-provider (seconds in better-auth, durations here).
const (
	DefaultCodeExpiresIn         = 600 * time.Second
	DefaultAccessTokenExpiresIn  = 3600 * time.Second
	DefaultRefreshTokenExpiresIn = 604800 * time.Second
	DefaultScope                 = "openid"
)

// DefaultScopes are always supported; Config.Scopes adds to them.
var DefaultScopes = []string{"openid", "profile", "email", "offline_access"}

// Logical model names of the plugin tables (better-auth's oidc-provider schema).
const (
	ModelOAuthApplication = "oauthApplication"
	ModelOAuthAccessToken = "oauthAccessToken"
	ModelOAuthConsent     = "oauthConsent"
)

// Client types stored in oauthApplication.type. Public clients have no secret and must use PKCE.
const (
	ClientTypeWeb            = "web"
	ClientTypeNative         = "native"
	ClientTypeUserAgentBased = "user-agent-based"
	ClientTypePublic         = "public"
)

// Client is an OAuth client: a row of oauthApplication or one of Config.TrustedClients (better-auth's Client).
type Client struct {
	// ClientID identifies the client.
	ClientID string
	// ClientSecret is the stored secret (plain, hashed or encrypted, see Config.StoreClientSecret). Trusted
	// clients hold it in plain text. Empty for public clients.
	ClientSecret string
	// Type is "web", "native", "user-agent-based" or "public".
	Type string
	// Name is shown on the consent screen.
	Name string
	// Icon is an optional logo URL.
	Icon string
	// Metadata is free-form client metadata (stored as JSON text).
	Metadata map[string]any
	// Disabled clients cannot authorize or get tokens.
	Disabled bool
	// RedirectURLs are the registered redirect URIs (whole URLs, compared exactly). They also bound
	// post_logout_redirect_uri at /oauth2/endsession.
	RedirectURLs []string
	// SkipConsent skips the consent screen. Only trusted clients use it.
	SkipConsent bool
}

// ConsentHTMLProps are passed to Config.GetConsentHTML (better-auth's getConsentHTML props).
type ConsentHTMLProps struct {
	ClientID       string
	ClientName     string
	ClientIcon     string
	ClientMetadata map[string]any
	// Code is the consent code to send back with POST /oauth2/consent (consent_code).
	Code   string
	Scopes []string
}

// SecretStorageMode is how client secrets are stored (better-auth's storeClientSecret string values).
type SecretStorageMode string

const (
	// SecretPlain stores the secret as is (the default).
	SecretPlain SecretStorageMode = "plain"
	// SecretHashed stores base64url(SHA-256(secret)) without padding.
	SecretHashed SecretStorageMode = "hashed"
	// SecretEncrypted stores the secret encrypted with the auth secret (better-auth's symmetricEncrypt).
	SecretEncrypted SecretStorageMode = "encrypted"
)

// ClientSecretStorage is better-auth's storeClientSecret: a mode, or custom functions. Hash wins over
// Encrypt/Decrypt, which win over Mode. The secret returned to the client at registration is never
// affected, only what the database holds.
type ClientSecretStorage struct {
	Mode SecretStorageMode
	// Hash is a custom one-way hash ({hash}); verification hashes the presented secret and compares.
	Hash func(ctx context.Context, secret string) (string, error)
	// Encrypt and Decrypt are a custom reversible encryption ({encrypt, decrypt}).
	Encrypt func(ctx context.Context, secret string) (string, error)
	Decrypt func(ctx context.Context, stored string) (string, error)
}

// ModelSchemaOptions renames a plugin table or its columns (better-auth's plugin `schema` option).
type ModelSchemaOptions struct {
	// ModelName is the table name.
	ModelName string
	// Fields maps logical field names to column names.
	Fields map[string]string
}

// AdditionalUserInfoClaimFunc returns extra claims for the userinfo endpoint and the id_token
// (better-auth's getAdditionalUserInfoClaim).
type AdditionalUserInfoClaimFunc func(ctx context.Context, user *models.User, scopes []string, client *Client) (map[string]any, error)

// Config holds better-auth's OIDCOptions.
type Config struct {
	// LoginPage is where users without a session are sent (with the authorization query). Required.
	LoginPage string
	// ConsentPage is where users are sent to consent (with consent_code, client_id and scope). When empty,
	// GetConsentHTML renders the consent screen.
	ConsentPage string
	// GetConsentHTML renders the consent screen when ConsentPage is empty.
	GetConsentHTML func(props ConsentHTMLProps) string

	// AccessTokenExpiresIn is the access token (and id_token) lifetime (default 1 hour).
	AccessTokenExpiresIn time.Duration
	// RefreshTokenExpiresIn is the refresh token lifetime (default 7 days).
	RefreshTokenExpiresIn time.Duration
	// CodeExpiresIn is the authorization code lifetime (default 10 minutes).
	CodeExpiresIn time.Duration

	// Scopes are supported scopes in addition to openid, profile, email and offline_access.
	Scopes []string
	// DefaultScope is used when the authorization request has no scope parameter (default "openid").
	DefaultScope string

	// AllowDynamicClientRegistration lets clients register at /oauth2/register without a session.
	AllowDynamicClientRegistration bool
	// RequirePKCE rejects authorization requests without code_challenge and token requests without
	// code_verifier (better-auth's default: off).
	RequirePKCE bool
	// AllowPlainCodeChallengeMethod accepts code_challenge_method=plain (and a missing method as plain).
	AllowPlainCodeChallengeMethod bool

	// GenerateClientID and GenerateClientSecret replace the random 32-letter values of /oauth2/register.
	GenerateClientID     func() string
	GenerateClientSecret func() string

	// GetAdditionalUserInfoClaim adds claims to the userinfo response and the id_token.
	GetAdditionalUserInfoClaim AdditionalUserInfoClaimFunc

	// TrustedClients are configured clients that are not looked up in the database; SkipConsent skips the
	// consent screen for them.
	TrustedClients []Client

	// StoreClientSecret selects how registered client secrets are stored (default plain).
	StoreClientSecret ClientSecretStorage

	// UseJWTPlugin signs id_tokens with the jwt plugin's key pair (JWKS at /jwks) instead of HS256 with the
	// client secret. The jwt plugin must be installed.
	UseJWTPlugin bool

	// Metadata overrides or adds keys of /.well-known/openid-configuration (better-auth's metadata).
	Metadata map[string]any

	// Schema renames the plugin tables or columns, keyed by logical model name (oauthApplication,
	// oauthAccessToken, oauthConsent).
	Schema map[string]ModelSchemaOptions
}

// WithDefaults fills unset options with better-auth's defaults.
func (c Config) WithDefaults() Config {
	if c.CodeExpiresIn <= 0 {
		c.CodeExpiresIn = DefaultCodeExpiresIn
	}
	if c.AccessTokenExpiresIn <= 0 {
		c.AccessTokenExpiresIn = DefaultAccessTokenExpiresIn
	}
	if c.RefreshTokenExpiresIn <= 0 {
		c.RefreshTokenExpiresIn = DefaultRefreshTokenExpiresIn
	}
	if c.DefaultScope == "" {
		c.DefaultScope = DefaultScope
	}
	if c.StoreClientSecret.Mode == "" {
		c.StoreClientSecret.Mode = SecretPlain
	}
	return c
}

// AllScopes returns the supported scopes: openid, profile, email, offline_access, then Scopes.
func (c Config) AllScopes() []string {
	out := append([]string{}, DefaultScopes...)
	return append(out, c.Scopes...)
}
