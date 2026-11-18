// Package dtos holds the request and response bodies of the sso endpoints (@better-auth/sso 1.6.16).
package dtos

import (
	"encoding/json"

	"github.com/better-go-auth/goauth/src/plugins/sso/config"
)

// ─── POST /sso/register ──────────────────────────────────────────────────────

// SSORegisterOIDCMapping is oidcConfig.mapping of a registration (id, email and name are required).
type SSORegisterOIDCMapping struct {
	_             struct{}       `additionalProperties:"true"`
	ID            string         `json:"id" doc:"Field mapping for user ID (defaults to 'sub')"`
	Email         string         `json:"email" doc:"Field mapping for email (defaults to 'email')"`
	EmailVerified string         `json:"emailVerified,omitempty" doc:"Field mapping for email verification (defaults to 'email_verified')"`
	Name          string         `json:"name" doc:"Field mapping for name (defaults to 'name')"`
	Image         string         `json:"image,omitempty" doc:"Field mapping for image (defaults to 'picture')"`
	ExtraFields   map[string]any `json:"extraFields,omitempty"`
}

// SSORegisterOIDCConfig is the oidcConfig of a registration.
type SSORegisterOIDCConfig struct {
	_                           struct{}                `additionalProperties:"true"`
	ClientID                    string                  `json:"clientId" doc:"The client ID"`
	ClientSecret                string                  `json:"clientSecret" doc:"The client secret"`
	AuthorizationEndpoint       string                  `json:"authorizationEndpoint,omitempty" format:"uri" doc:"The authorization endpoint"`
	TokenEndpoint               string                  `json:"tokenEndpoint,omitempty" format:"uri" doc:"The token endpoint"`
	UserInfoEndpoint            string                  `json:"userInfoEndpoint,omitempty" format:"uri" doc:"The user info endpoint"`
	TokenEndpointAuthentication string                  `json:"tokenEndpointAuthentication,omitempty" enum:"client_secret_post,client_secret_basic"`
	JWKSEndpoint                string                  `json:"jwksEndpoint,omitempty" format:"uri" doc:"The JWKS endpoint"`
	DiscoveryEndpoint           string                  `json:"discoveryEndpoint,omitempty" format:"uri"`
	SkipDiscovery               bool                    `json:"skipDiscovery,omitempty" doc:"Skip OIDC discovery during registration. When true, you must provide authorizationEndpoint, tokenEndpoint, and jwksEndpoint manually."`
	Scopes                      []string                `json:"scopes,omitempty" doc:"The scopes to request. Defaults to ['openid', 'email', 'profile', 'offline_access']"`
	PKCE                        *bool                   `json:"pkce,omitempty" doc:"Whether to use PKCE for the authorization flow"`
	Mapping                     *SSORegisterOIDCMapping `json:"mapping,omitempty"`
}

// SSORegisterSAMLMapping is samlConfig.mapping of a registration (id, email and name are required).
type SSORegisterSAMLMapping struct {
	_             struct{}       `additionalProperties:"true"`
	ID            string         `json:"id" doc:"Field mapping for user ID (defaults to 'nameID')"`
	Email         string         `json:"email" doc:"Field mapping for email (defaults to 'email')"`
	EmailVerified string         `json:"emailVerified,omitempty" doc:"Field mapping for email verification"`
	Name          string         `json:"name" doc:"Field mapping for name (defaults to 'displayName')"`
	FirstName     string         `json:"firstName,omitempty" doc:"Field mapping for first name (defaults to 'givenName')"`
	LastName      string         `json:"lastName,omitempty" doc:"Field mapping for last name (defaults to 'surname')"`
	ExtraFields   map[string]any `json:"extraFields,omitempty"`
}

// SSOIDPMetadataInput is samlConfig.idpMetadata.
type SSOIDPMetadataInput struct {
	_                    struct{}             `additionalProperties:"true"`
	Metadata             string               `json:"metadata,omitempty"`
	EntityID             string               `json:"entityID,omitempty"`
	Cert                 string               `json:"cert,omitempty"`
	PrivateKey           string               `json:"privateKey,omitempty"`
	PrivateKeyPass       string               `json:"privateKeyPass,omitempty"`
	IsAssertionEncrypted *bool                `json:"isAssertionEncrypted,omitempty"`
	EncPrivateKey        string               `json:"encPrivateKey,omitempty"`
	EncPrivateKeyPass    string               `json:"encPrivateKeyPass,omitempty"`
	SingleSignOnService  []config.SAMLService `json:"singleSignOnService,omitempty" doc:"Single Sign-On service configuration"`
}

// SSOSPMetadataInput is samlConfig.spMetadata.
type SSOSPMetadataInput struct {
	_                    struct{} `additionalProperties:"true"`
	Metadata             string   `json:"metadata,omitempty"`
	EntityID             string   `json:"entityID,omitempty"`
	Binding              string   `json:"binding,omitempty"`
	PrivateKey           string   `json:"privateKey,omitempty"`
	PrivateKeyPass       string   `json:"privateKeyPass,omitempty"`
	IsAssertionEncrypted *bool    `json:"isAssertionEncrypted,omitempty"`
	EncPrivateKey        string   `json:"encPrivateKey,omitempty"`
	EncPrivateKeyPass    string   `json:"encPrivateKeyPass,omitempty"`
}

// SSORegisterSAMLConfig is the samlConfig of a registration.
type SSORegisterSAMLConfig struct {
	_                    struct{}                `additionalProperties:"true"`
	EntryPoint           string                  `json:"entryPoint" doc:"The entry point of the provider"`
	Cert                 string                  `json:"cert" doc:"The certificate of the provider"`
	CallbackURL          string                  `json:"callbackUrl" doc:"The callback URL of the provider"`
	Audience             string                  `json:"audience,omitempty"`
	IDPMetadata          *SSOIDPMetadataInput    `json:"idpMetadata,omitempty"`
	SPMetadata           SSOSPMetadataInput      `json:"spMetadata"`
	WantAssertionsSigned *bool                   `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned  *bool                   `json:"authnRequestsSigned,omitempty"`
	SignatureAlgorithm   string                  `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm      string                  `json:"digestAlgorithm,omitempty"`
	IdentifierFormat     string                  `json:"identifierFormat,omitempty"`
	PrivateKey           string                  `json:"privateKey,omitempty"`
	DecryptionPvk        string                  `json:"decryptionPvk,omitempty"`
	AdditionalParams     map[string]any          `json:"additionalParams,omitempty"`
	Mapping              *SSORegisterSAMLMapping `json:"mapping,omitempty"`
}

// SSORegisterInput is the body of POST /sso/register.
type SSORegisterInput struct {
	_                struct{}               `additionalProperties:"true"`
	ProviderID       string                 `json:"providerId" doc:"The ID of the provider. This is used to identify the provider during login and callback"`
	Issuer           string                 `json:"issuer" doc:"The issuer of the provider"`
	Domain           string                 `json:"domain" doc:"The domain(s) of the provider. For enterprise multi-domain SSO where a single IdP serves multiple email domains, use comma-separated values (e.g., 'company.com,subsidiary.com,acquired-company.com')"`
	OIDCConfig       *SSORegisterOIDCConfig `json:"oidcConfig,omitempty"`
	SAMLConfig       *SSORegisterSAMLConfig `json:"samlConfig,omitempty"`
	OrganizationID   string                 `json:"organizationId,omitempty" doc:"If organization plugin is enabled, the organization id to link the provider to"`
	OverrideUserInfo bool                   `json:"overrideUserInfo,omitempty" doc:"Override user info with the provider info. Defaults to false"`
}

// SSOProviderResponse is the body of POST /sso/register: the stored provider with parsed configs.
type SSOProviderResponse struct {
	ID                      string          `json:"id"`
	Issuer                  string          `json:"issuer"`
	OIDCConfig              json.RawMessage `json:"oidcConfig"`
	SAMLConfig              json.RawMessage `json:"samlConfig"`
	UserID                  string          `json:"userId"`
	ProviderID              string          `json:"providerId"`
	OrganizationID          *string         `json:"organizationId"`
	Domain                  string          `json:"domain"`
	DomainVerified          *bool           `json:"domainVerified,omitempty"`
	RedirectURI             string          `json:"redirectURI"`
	DomainVerificationToken string          `json:"domainVerificationToken,omitempty"`
}

// ─── POST /sign-in/sso ───────────────────────────────────────────────────────

// SSOSignInInput is the body of POST /sign-in/sso.
type SSOSignInInput struct {
	_                  struct{} `additionalProperties:"true"`
	Email              string   `json:"email,omitempty" doc:"The email address to sign in with. This is used to identify the issuer to sign in with. It's optional if the issuer is provided"`
	OrganizationSlug   string   `json:"organizationSlug,omitempty" doc:"The slug of the organization to sign in with"`
	ProviderID         string   `json:"providerId,omitempty" doc:"The ID of the provider to sign in with. This can be provided instead of email or issuer"`
	Domain             string   `json:"domain,omitempty" doc:"The domain of the provider."`
	CallbackURL        string   `json:"callbackURL" doc:"The URL to redirect to after login"`
	ErrorCallbackURL   string   `json:"errorCallbackURL,omitempty" doc:"The URL to redirect to after login"`
	NewUserCallbackURL string   `json:"newUserCallbackURL,omitempty" doc:"The URL to redirect to after login if the user is new"`
	Scopes             []string `json:"scopes,omitempty" doc:"Scopes to request from the provider."`
	LoginHint          string   `json:"loginHint,omitempty" doc:"Login hint to send to the identity provider (e.g., email or identifier). If supported, will be sent as 'login_hint'."`
	RequestSignUp      bool     `json:"requestSignUp,omitempty" doc:"Explicitly request sign-up. Useful when disableImplicitSignUp is true for this provider"`
	ProviderType       string   `json:"providerType,omitempty" enum:"oidc,saml"`
}

// SSORedirectResponse is {url, redirect: true}.
type SSORedirectResponse struct {
	URL      string `json:"url" doc:"The authorization URL to redirect the user to for SSO sign-in"`
	Redirect bool   `json:"redirect" doc:"Indicates that the client should redirect to the provided URL"`
}

// ─── provider management ─────────────────────────────────────────────────────

// SSOSanitizedOIDCConfig is the public part of an OIDC config.
type SSOSanitizedOIDCConfig struct {
	DiscoveryEndpoint           string   `json:"discoveryEndpoint,omitempty"`
	ClientIDLastFour            string   `json:"clientIdLastFour"`
	PKCE                        *bool    `json:"pkce,omitempty"`
	AuthorizationEndpoint       string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint               string   `json:"tokenEndpoint,omitempty"`
	UserInfoEndpoint            string   `json:"userInfoEndpoint,omitempty"`
	JWKSEndpoint                string   `json:"jwksEndpoint,omitempty"`
	Scopes                      []string `json:"scopes,omitempty"`
	TokenEndpointAuthentication string   `json:"tokenEndpointAuthentication,omitempty"`
}

// SSOCertificateInfo describes the IdP signing certificate (or {error}).
type SSOCertificateInfo struct {
	FingerprintSha256  string `json:"fingerprintSha256,omitempty"`
	NotBefore          string `json:"notBefore,omitempty"`
	NotAfter           string `json:"notAfter,omitempty"`
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm,omitempty"`
	Error              string `json:"error,omitempty"`
}

// SSOSanitizedSAMLConfig is the public part of a SAML config.
type SSOSanitizedSAMLConfig struct {
	EntryPoint           string             `json:"entryPoint,omitempty"`
	CallbackURL          string             `json:"callbackUrl,omitempty"`
	Audience             string             `json:"audience,omitempty"`
	WantAssertionsSigned *bool              `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned  *bool              `json:"authnRequestsSigned,omitempty"`
	IdentifierFormat     string             `json:"identifierFormat,omitempty"`
	SignatureAlgorithm   string             `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm      string             `json:"digestAlgorithm,omitempty"`
	Certificate          SSOCertificateInfo `json:"certificate"`
}

// SSOSanitizedProvider is better-auth's sanitizeProvider output (secrets removed).
type SSOSanitizedProvider struct {
	ProviderID     string                  `json:"providerId"`
	Type           string                  `json:"type"`
	Issuer         string                  `json:"issuer"`
	Domain         string                  `json:"domain"`
	OrganizationID *string                 `json:"organizationId"`
	DomainVerified bool                    `json:"domainVerified"`
	OIDCConfig     *SSOSanitizedOIDCConfig `json:"oidcConfig,omitempty"`
	SAMLConfig     *SSOSanitizedSAMLConfig `json:"samlConfig,omitempty"`
	SPMetadataURL  string                  `json:"spMetadataUrl"`
}

// SSOListProvidersResponse is the body of GET /sso/providers.
type SSOListProvidersResponse struct {
	Providers []SSOSanitizedProvider `json:"providers"`
}

// SSOProviderIDInput is {providerId}.
type SSOProviderIDInput struct {
	_          struct{} `additionalProperties:"true"`
	ProviderID string   `json:"providerId"`
}

// SSOUpdateOIDCConfig is the oidcConfig of POST /sso/update-provider (every field optional).
type SSOUpdateOIDCConfig struct {
	_                           struct{}            `additionalProperties:"true"`
	ClientID                    string              `json:"clientId,omitempty"`
	ClientSecret                string              `json:"clientSecret,omitempty"`
	AuthorizationEndpoint       string              `json:"authorizationEndpoint,omitempty" format:"uri"`
	TokenEndpoint               string              `json:"tokenEndpoint,omitempty" format:"uri"`
	UserInfoEndpoint            string              `json:"userInfoEndpoint,omitempty" format:"uri"`
	TokenEndpointAuthentication string              `json:"tokenEndpointAuthentication,omitempty" enum:"client_secret_post,client_secret_basic"`
	JWKSEndpoint                string              `json:"jwksEndpoint,omitempty" format:"uri"`
	DiscoveryEndpoint           string              `json:"discoveryEndpoint,omitempty" format:"uri"`
	Scopes                      []string            `json:"scopes,omitempty"`
	PKCE                        *bool               `json:"pkce,omitempty"`
	OverrideUserInfo            *bool               `json:"overrideUserInfo,omitempty"`
	Mapping                     *config.OIDCMapping `json:"mapping,omitempty"`
}

// SSOUpdateSAMLConfig is the samlConfig of POST /sso/update-provider (every field optional).
type SSOUpdateSAMLConfig struct {
	_                    struct{}             `additionalProperties:"true"`
	EntryPoint           string               `json:"entryPoint,omitempty" format:"uri"`
	Cert                 string               `json:"cert,omitempty"`
	CallbackURL          string               `json:"callbackUrl,omitempty" format:"uri"`
	Audience             string               `json:"audience,omitempty"`
	IDPMetadata          *SSOIDPMetadataInput `json:"idpMetadata,omitempty"`
	SPMetadata           *SSOSPMetadataInput  `json:"spMetadata,omitempty"`
	WantAssertionsSigned *bool                `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned  *bool                `json:"authnRequestsSigned,omitempty"`
	SignatureAlgorithm   string               `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm      string               `json:"digestAlgorithm,omitempty"`
	IdentifierFormat     string               `json:"identifierFormat,omitempty"`
	PrivateKey           string               `json:"privateKey,omitempty"`
	DecryptionPvk        string               `json:"decryptionPvk,omitempty"`
	AdditionalParams     map[string]any       `json:"additionalParams,omitempty"`
	Mapping              *config.SAMLMapping  `json:"mapping,omitempty"`
}

// SSOUpdateProviderInput is the body of POST /sso/update-provider.
type SSOUpdateProviderInput struct {
	_          struct{}             `additionalProperties:"true"`
	ProviderID string               `json:"providerId"`
	Issuer     string               `json:"issuer,omitempty" format:"uri"`
	Domain     *string              `json:"domain,omitempty"`
	OIDCConfig *SSOUpdateOIDCConfig `json:"oidcConfig,omitempty"`
	SAMLConfig *SSOUpdateSAMLConfig `json:"samlConfig,omitempty"`
}

// SSOSuccessResponse is {success: true}.
type SSOSuccessResponse struct {
	Success bool `json:"success"`
}

// SSODomainVerificationTokenResponse is the body of POST /sso/request-domain-verification.
type SSODomainVerificationTokenResponse struct {
	DomainVerificationToken string `json:"domainVerificationToken"`
}

// SSOInitiateSLOInput is the body of POST /sso/saml2/logout/{providerId}.
type SSOInitiateSLOInput struct {
	_           struct{} `additionalProperties:"true"`
	CallbackURL string   `json:"callbackURL,omitempty"`
}
