// Package config holds the options of the sso plugin (better-auth's SSOOptions, @better-auth/sso 1.6.16) and
// the provider configurations stored in the ssoProvider table (oidcConfig / samlConfig JSON).
package config

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// Defaults of better-auth's sso plugin.
const (
	// DefaultModelName is the ssoProvider model name.
	DefaultModelName = "ssoProvider"
	// DefaultProvidersLimit is providersLimit's default.
	DefaultProvidersLimit = 10
	// DefaultTokenPrefix is domainVerification.tokenPrefix's default.
	DefaultTokenPrefix = "better-auth-token"
	// DefaultClockSkew is saml.clockSkew's default (5 minutes).
	DefaultClockSkew = 5 * time.Minute
	// DefaultRequestTTL is saml.requestTTL's default (5 minutes).
	DefaultRequestTTL = 5 * time.Minute
	// DefaultLogoutRequestTTL is saml.logoutRequestTTL's default (5 minutes).
	DefaultLogoutRequestTTL = 5 * time.Minute
	// DefaultMaxResponseSize is saml.maxResponseSize's default (256 KB).
	DefaultMaxResponseSize = 256 * 1024
	// DefaultMaxMetadataSize is saml.maxMetadataSize's default (100 KB).
	DefaultMaxMetadataSize = 100 * 1024
	// DefaultAssertionTTL is how long a used assertion ID is remembered when it has no NotOnOrAfter.
	DefaultAssertionTTL = 15 * time.Minute
)

// ─── Stored provider configuration ───────────────────────────────────────────

// OIDCMapping maps provider claims to user fields (better-auth's oidcConfig.mapping).
type OIDCMapping struct {
	ID            string         `json:"id,omitempty"`
	Email         string         `json:"email,omitempty"`
	EmailVerified string         `json:"emailVerified,omitempty"`
	Name          string         `json:"name,omitempty"`
	Image         string         `json:"image,omitempty"`
	ExtraFields   map[string]any `json:"extraFields,omitempty"`
}

// OIDCConfig is the oidcConfig JSON stored on an ssoProvider (better-auth's OIDCConfig).
type OIDCConfig struct {
	Issuer                string `json:"issuer,omitempty"`
	ClientID              string `json:"clientId,omitempty"`
	ClientSecret          string `json:"clientSecret,omitempty"`
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty"`
	// TokenEndpointAuthentication is "client_secret_basic" or "client_secret_post".
	TokenEndpointAuthentication string       `json:"tokenEndpointAuthentication,omitempty"`
	JWKSEndpoint                string       `json:"jwksEndpoint,omitempty"`
	PKCE                        *bool        `json:"pkce,omitempty"`
	DiscoveryEndpoint           string       `json:"discoveryEndpoint,omitempty"`
	Mapping                     *OIDCMapping `json:"mapping,omitempty"`
	Scopes                      []string     `json:"scopes,omitempty"`
	UserInfoEndpoint            string       `json:"userInfoEndpoint,omitempty"`
	OverrideUserInfo            *bool        `json:"overrideUserInfo,omitempty"`
}

// PKCEEnabled reports pkce (unset counts as off at sign-in, like better-auth's `config.pkce ? ... : undefined`).
func (c OIDCConfig) PKCEEnabled() bool { return c.PKCE != nil && *c.PKCE }

// SAMLService is one IdP endpoint (singleSignOnService / singleLogoutService entries).
type SAMLService struct {
	Binding  string `json:"Binding"`
	Location string `json:"Location"`
}

// IDPMetadata is samlConfig.idpMetadata.
type IDPMetadata struct {
	// Metadata is the IdP metadata XML (wins over the other fields).
	Metadata             string        `json:"metadata,omitempty"`
	EntityID             string        `json:"entityID,omitempty"`
	Cert                 string        `json:"cert,omitempty"`
	PrivateKey           string        `json:"privateKey,omitempty"`
	PrivateKeyPass       string        `json:"privateKeyPass,omitempty"`
	IsAssertionEncrypted *bool         `json:"isAssertionEncrypted,omitempty"`
	EncPrivateKey        string        `json:"encPrivateKey,omitempty"`
	EncPrivateKeyPass    string        `json:"encPrivateKeyPass,omitempty"`
	SingleSignOnService  []SAMLService `json:"singleSignOnService,omitempty"`
	SingleLogoutService  []SAMLService `json:"singleLogoutService,omitempty"`
}

// SPMetadata is samlConfig.spMetadata.
type SPMetadata struct {
	// Metadata is the SP metadata XML served by /sso/saml2/sp/metadata as is.
	Metadata             string `json:"metadata,omitempty"`
	EntityID             string `json:"entityID,omitempty"`
	Binding              string `json:"binding,omitempty"`
	PrivateKey           string `json:"privateKey,omitempty"`
	PrivateKeyPass       string `json:"privateKeyPass,omitempty"`
	IsAssertionEncrypted *bool  `json:"isAssertionEncrypted,omitempty"`
	EncPrivateKey        string `json:"encPrivateKey,omitempty"`
	EncPrivateKeyPass    string `json:"encPrivateKeyPass,omitempty"`
}

// SAMLMapping maps assertion attributes to user fields (better-auth's samlConfig.mapping).
type SAMLMapping struct {
	ID            string         `json:"id,omitempty"`
	Email         string         `json:"email,omitempty"`
	EmailVerified string         `json:"emailVerified,omitempty"`
	Name          string         `json:"name,omitempty"`
	FirstName     string         `json:"firstName,omitempty"`
	LastName      string         `json:"lastName,omitempty"`
	ExtraFields   map[string]any `json:"extraFields,omitempty"`
}

// SAMLConfig is the samlConfig JSON stored on an ssoProvider (better-auth's SAMLConfig).
type SAMLConfig struct {
	Issuer      string `json:"issuer,omitempty"`
	EntryPoint  string `json:"entryPoint,omitempty"`
	Cert        string `json:"cert,omitempty"`
	CallbackURL string `json:"callbackUrl,omitempty"`
	Audience    string `json:"audience,omitempty"`
	// IDPMetadata and SPMetadata configure the identity provider and this service provider.
	IDPMetadata          *IDPMetadata   `json:"idpMetadata,omitempty"`
	SPMetadata           *SPMetadata    `json:"spMetadata,omitempty"`
	WantAssertionsSigned *bool          `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned  *bool          `json:"authnRequestsSigned,omitempty"`
	SignatureAlgorithm   string         `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm      string         `json:"digestAlgorithm,omitempty"`
	IdentifierFormat     string         `json:"identifierFormat,omitempty"`
	PrivateKey           string         `json:"privateKey,omitempty"`
	DecryptionPvk        string         `json:"decryptionPvk,omitempty"`
	AdditionalParams     map[string]any `json:"additionalParams,omitempty"`
	Mapping              *SAMLMapping   `json:"mapping,omitempty"`
}

// ─── Plugin options ──────────────────────────────────────────────────────────

// Provider is an SSO provider as the plugin works with it (a stored ssoProvider row with parsed configs, or
// a DefaultSSO entry).
type Provider struct {
	ID             string
	Issuer         string
	Domain         string
	ProviderID     string
	UserID         string
	OrganizationID string
	// DomainVerified is nil when domain verification is disabled (the column does not exist).
	DomainVerified *bool
	OIDCConfig     *OIDCConfig
	SAMLConfig     *SAMLConfig
}

// IsDomainVerified reports `"domainVerified" in provider && provider.domainVerified`.
func (p *Provider) IsDomainVerified() bool {
	return p != nil && p.DomainVerified != nil && *p.DomainVerified
}

// ProvisionUserData is passed to ProvisionUser and OrganizationProvisioning.GetRole.
type ProvisionUserData struct {
	// User is the signed-in user.
	User *models.User
	// UserInfo is the mapped provider profile (id, email, name, emailVerified, image and the extra fields).
	UserInfo map[string]any
	// Token is the OIDC token response (nil for SAML).
	Token *providers.OAuth2Tokens
	// Provider is the SSO provider used.
	Provider *Provider
}

// OrganizationProvisioning is better-auth's organizationProvisioning.
type OrganizationProvisioning struct {
	// Disabled stops adding SSO users to the provider's organization.
	Disabled bool
	// DefaultRole is the member role ("member" by default).
	DefaultRole string
	// GetRole computes the role per user (wins over DefaultRole).
	GetRole func(ctx context.Context, data ProvisionUserData) (string, error)
}

// DefaultProvider is one defaultSSO entry: a provider configured in code that wins over the database.
type DefaultProvider struct {
	// Domain matches sign-in requests by email domain.
	Domain     string
	ProviderID string
	SAMLConfig *SAMLConfig
	OIDCConfig *OIDCConfig
}

// DomainVerification is better-auth's domainVerification.
type DomainVerification struct {
	// Enabled adds the domainVerified column and the /sso/request-domain-verification and
	// /sso/verify-domain endpoints; providers must verify their domain before users can sign in.
	Enabled bool
	// TokenPrefix names the DNS TXT record "_<prefix>-<providerId>" (default "better-auth-token").
	TokenPrefix string
	// LookupTXT resolves DNS TXT records (goauth extra; default net.DefaultResolver.LookupTXT).
	LookupTXT func(ctx context.Context, name string) ([]string, error)
}

// AlgorithmOptions is better-auth's saml.algorithms (AlgorithmValidationOptions).
type AlgorithmOptions struct {
	// OnDeprecated is "warn" (default), "reject" or "allow" for SHA-1 / RSA1_5 / 3DES.
	OnDeprecated string
	// Allowed* replace the default checks with allow-lists (URIs, or short names for config values).
	AllowedSignatureAlgorithms      []string
	AllowedDigestAlgorithms         []string
	AllowedKeyEncryptionAlgorithms  []string
	AllowedDataEncryptionAlgorithms []string
}

// SAMLOptions is better-auth's saml option block.
type SAMLOptions struct {
	// EnableInResponseToValidation tracks AuthnRequest IDs and validates InResponseTo (default true).
	EnableInResponseToValidation *bool
	// AllowIdpInitiated accepts responses without InResponseTo (default true).
	AllowIdpInitiated *bool
	// RequestTTL is how long an AuthnRequest ID stays valid (default 5 minutes).
	RequestTTL time.Duration
	// ClockSkew is the NotBefore / NotOnOrAfter tolerance (default 5 minutes).
	ClockSkew time.Duration
	// RequireTimestamps rejects assertions without NotBefore / NotOnOrAfter.
	RequireTimestamps bool
	// Algorithms configures the signature / encryption algorithm checks.
	Algorithms *AlgorithmOptions
	// MaxResponseSize limits SAMLResponse (default 256 KB).
	MaxResponseSize int
	// MaxMetadataSize limits idpMetadata.metadata (default 100 KB).
	MaxMetadataSize int
	// EnableSingleLogout enables SAML Single Logout (/sso/saml2/sp/slo, /sso/saml2/logout).
	EnableSingleLogout bool
	// LogoutRequestTTL is how long an SP LogoutRequest ID is remembered (default 5 minutes).
	LogoutRequestTTL time.Duration
	// WantLogoutRequestSigned / WantLogoutResponseSigned are better-auth's flags. goauth's SAML library
	// always requires IdP logout messages to be signed, so they are informational.
	WantLogoutRequestSigned  bool
	WantLogoutResponseSigned bool
}

// Fields renames the ssoProvider columns (better-auth's fields option).
type Fields struct {
	Issuer         string
	OIDCConfig     string
	SAMLConfig     string
	UserID         string
	ProviderID     string
	OrganizationID string
	Domain         string
}

// SSOConfig mirrors better-auth's SSOOptions.
type SSOConfig struct {
	// ProvisionUser runs after an SSO sign-in that created the user (or every sign-in with
	// ProvisionUserOnEveryLogin).
	ProvisionUser func(ctx context.Context, data ProvisionUserData) error
	// ProvisionUserOnEveryLogin calls ProvisionUser on every SSO sign-in.
	ProvisionUserOnEveryLogin bool
	// OrganizationProvisioning adds SSO users to the provider's organization (organization plugin).
	OrganizationProvisioning *OrganizationProvisioning
	// DefaultSSO are providers configured in code; they win over the database.
	DefaultSSO []DefaultProvider
	// DefaultOverrideUserInfo is overrideUserInfo for providers registered without it.
	DefaultOverrideUserInfo bool
	// DisableImplicitSignUp only creates users when sign-in sends requestSignUp: true.
	DisableImplicitSignUp bool
	// ModelName is the ssoProvider model (table) name.
	ModelName string
	// Fields renames columns.
	Fields Fields
	// ProvidersLimit is the maximum number of providers a user may register (default 10; 0 with
	// ProvidersLimitSet disables registration).
	ProvidersLimit int
	// ProvidersLimitSet marks ProvidersLimit as configured, so 0 disables registration.
	ProvidersLimitSet bool
	// ProvidersLimitFunc computes the limit per user (wins over ProvidersLimit).
	ProvidersLimitFunc func(ctx context.Context, user *models.User) (int, error)
	// TrustEmailVerified trusts the provider's email_verified claim (deprecated upstream).
	TrustEmailVerified bool
	// DomainVerification enables domain verification.
	DomainVerification DomainVerification
	// RedirectURI is a shared OIDC redirect URI (path or URL) used instead of /sso/callback/{providerId}.
	RedirectURI string
	// SAML configures the SAML flows.
	SAML SAMLOptions
	// HTTPClient is used for OIDC discovery, token, userinfo and JWKS requests (goauth extra; default 10s
	// timeout, redirects refused).
	HTTPClient *http.Client
	// LookupHost resolves host names for the SSRF check of OIDC endpoints (goauth extra; default
	// net.DefaultResolver.LookupHost).
	LookupHost func(ctx context.Context, host string) ([]string, error)
}

// WithDefaults returns cfg with better-auth's defaults filled in.
func (cfg SSOConfig) WithDefaults() SSOConfig {
	// Step 1: names and limits
	if cfg.ModelName == "" {
		cfg.ModelName = DefaultModelName
	}
	if !cfg.ProvidersLimitSet && cfg.ProvidersLimit == 0 {
		cfg.ProvidersLimit = DefaultProvidersLimit
	}
	if cfg.DomainVerification.TokenPrefix == "" {
		cfg.DomainVerification.TokenPrefix = DefaultTokenPrefix
	}
	if cfg.DomainVerification.LookupTXT == nil {
		cfg.DomainVerification.LookupTXT = net.DefaultResolver.LookupTXT
	}
	// Step 2: SAML limits and TTLs
	if cfg.SAML.RequestTTL <= 0 {
		cfg.SAML.RequestTTL = DefaultRequestTTL
	}
	if cfg.SAML.ClockSkew <= 0 {
		cfg.SAML.ClockSkew = DefaultClockSkew
	}
	if cfg.SAML.LogoutRequestTTL <= 0 {
		cfg.SAML.LogoutRequestTTL = DefaultLogoutRequestTTL
	}
	if cfg.SAML.MaxResponseSize <= 0 {
		cfg.SAML.MaxResponseSize = DefaultMaxResponseSize
	}
	if cfg.SAML.MaxMetadataSize <= 0 {
		cfg.SAML.MaxMetadataSize = DefaultMaxMetadataSize
	}
	// Step 3: network
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if cfg.LookupHost == nil {
		cfg.LookupHost = net.DefaultResolver.LookupHost
	}
	return cfg
}

// InResponseToValidation reports saml.enableInResponseToValidation (default true).
func (s SAMLOptions) InResponseToValidation() bool {
	return s.EnableInResponseToValidation == nil || *s.EnableInResponseToValidation
}

// IdpInitiatedAllowed reports saml.allowIdpInitiated (default true).
func (s SAMLOptions) IdpInitiatedAllowed() bool {
	return s.AllowIdpInitiated == nil || *s.AllowIdpInitiated
}

// Bool returns a pointer to b.
func Bool(b bool) *bool { return &b }
