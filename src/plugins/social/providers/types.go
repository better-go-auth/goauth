// Package providers implements better-auth's social (OAuth 2.0 / OpenID Connect) providers:
// google, github, discord, microsoft (Entra ID), apple, facebook, gitlab and a fully configurable
// generic OAuth2/OIDC provider. Every endpoint URL can be overridden so tests can point a provider at
// an httptest fake.
package providers

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// OAuth2Tokens mirrors better-auth's OAuth2Tokens (getOAuth2Tokens).
type OAuth2Tokens struct {
	TokenType             string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scopes                []string
	IDToken               string
	// Raw is the decoded token endpoint response.
	Raw map[string]any
}

// UserInfo is the normalized user a provider returns (better-auth's OAuth2UserInfo).
type UserInfo struct {
	ID            string
	Name          string
	Email         string
	Image         string
	EmailVerified bool
	// Extra holds additional user fields returned by MapProfileToUser (e.g. "firstName", "username").
	// They are copied onto the goauth user when it is created or its info is overridden.
	Extra map[string]any
}

// UserInfoResult is what GetUserInfo returns: the normalized user plus the raw provider profile.
type UserInfoResult struct {
	User UserInfo
	Data map[string]any
}

// AppleUser is the `user` form field Apple posts on the first authorization (and the idToken.user body field).
type AppleUser struct {
	Name  *AppleUserName `json:"name,omitempty"`
	Email string         `json:"email,omitempty"`
}

// AppleUserName is the name part of AppleUser.
type AppleUserName struct {
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

// UserInfoInput is the token set passed to GetUserInfo (better-auth's `{...tokens, user}`).
type UserInfoInput struct {
	OAuth2Tokens
	User *AppleUser
}

// AuthorizationURLInput carries the per-request parameters of CreateAuthorizationURL.
type AuthorizationURLInput struct {
	State        string
	CodeVerifier string
	RedirectURI  string
	Scopes       []string
	LoginHint    string
	Display      string
}

// ValidateCodeInput carries the parameters of the authorization code exchange.
type ValidateCodeInput struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
	DeviceID     string
}

// Provider is a social sign-in provider (better-auth's OAuthProvider).
type Provider interface {
	// ID is the provider id stored on accounts and used in /callback/{id}.
	ID() string
	// Name is a human readable name.
	Name() string
	// CreateAuthorizationURL builds the URL the user is redirected to.
	CreateAuthorizationURL(ctx context.Context, in AuthorizationURLInput) (*url.URL, error)
	// ValidateAuthorizationCode exchanges an authorization code for tokens. A nil result means invalid.
	ValidateAuthorizationCode(ctx context.Context, in ValidateCodeInput) (*OAuth2Tokens, error)
	// RefreshAccessToken trades a refresh token for new tokens.
	RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuth2Tokens, error)
	// GetUserInfo returns the user behind a token set (nil when it cannot be resolved).
	GetUserInfo(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error)
	// Options returns the shared provider options (sign-up and user-info policies).
	Options() *ProviderOptions
}

// IDTokenVerifier is implemented by providers supporting direct id_token sign-in (better-auth's verifyIdToken).
type IDTokenVerifier interface {
	VerifyIDToken(ctx context.Context, token, nonce string) (bool, error)
}

// idTokenSupport lets a provider implement IDTokenVerifier yet report that it is not configured for it
// (e.g. a generic provider without a JWKS URL).
type idTokenSupport interface {
	SupportsIDToken() bool
}

// AsIDTokenVerifier returns p's id_token verifier, or false when p does not support id_token sign-in.
func AsIDTokenVerifier(p Provider) (IDTokenVerifier, bool) {
	v, ok := p.(IDTokenVerifier)
	if !ok {
		return nil, false
	}
	if s, ok := p.(idTokenSupport); ok && !s.SupportsIDToken() {
		return nil, false
	}
	return v, true
}

// ProviderOptions are the options shared by every provider (better-auth's ProviderOptions).
type ProviderOptions struct {
	ClientID     string
	ClientSecret string
	// Scope is appended to the provider's default scopes.
	Scope []string
	// DisableDefaultScope drops the provider's default scopes.
	DisableDefaultScope bool
	// RedirectURI overrides "<baseURL>/callback/<id>".
	RedirectURI string
	Prompt      string
	AccessType  string
	Display     string

	// DisableSignUp refuses to create users through this provider.
	DisableSignUp bool
	// DisableImplicitSignUp only creates users when the sign-in request sets requestSignUp.
	DisableImplicitSignUp bool
	// DisableIDTokenSignIn turns off direct id_token sign-in.
	DisableIDTokenSignIn bool
	// OverrideUserInfoOnSignIn updates the local user with the provider profile on every sign-in.
	OverrideUserInfoOnSignIn bool

	// MapProfileToUser maps the raw provider profile to user fields. Known keys ("id", "name", "email",
	// "image", "emailVerified") override the normalized user; other keys land in UserInfo.Extra.
	MapProfileToUser func(profile map[string]any) map[string]any
	// GetUserInfo replaces the provider's user info lookup.
	GetUserInfo func(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error)
	// RefreshAccessToken replaces the provider's refresh implementation.
	RefreshAccessToken func(ctx context.Context, refreshToken string) (*OAuth2Tokens, error)
	// VerifyIDToken replaces the provider's id_token verification.
	VerifyIDToken func(ctx context.Context, token, nonce string) (bool, error)

	// Endpoint overrides (empty = the provider's production endpoint).
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSEndpoint          string

	// HTTPClient is used for every provider call (default: a client with a 10s timeout).
	HTTPClient *http.Client
}

// Options returns o itself so embedding structs satisfy part of Provider.
func (o *ProviderOptions) Options() *ProviderOptions { return o }

func (o *ProviderOptions) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return defaultClient
}

var defaultClient = &http.Client{Timeout: 10 * time.Second}

// pick returns override when set, else def.
func pick(override, def string) string {
	if override != "" {
		return override
	}
	return def
}

// scopes builds the scope list: defaults (unless disabled) + configured scopes + request scopes.
func (o *ProviderOptions) scopes(defaults []string, requested []string) []string {
	var out []string
	if !o.DisableDefaultScope {
		out = append(out, defaults...)
	}
	out = append(out, o.Scope...)
	out = append(out, requested...)
	return out
}

// applyProfileMap runs MapProfileToUser and merges its result into user (better-auth's `...userMap`).
func (o *ProviderOptions) applyProfileMap(user *UserInfo, profile map[string]any) {
	if o.MapProfileToUser == nil {
		return
	}
	ApplyUserMap(user, o.MapProfileToUser(profile))
}

// ApplyUserMap merges a mapProfileToUser result into user.
func ApplyUserMap(user *UserInfo, m map[string]any) {
	for k, v := range m {
		switch k {
		case "id":
			user.ID = stringOf(v)
		case "name":
			user.Name = stringOf(v)
		case "email":
			user.Email = stringOf(v)
		case "image":
			user.Image = stringOf(v)
		case "emailVerified":
			user.EmailVerified = boolOf(v)
		default:
			if user.Extra == nil {
				user.Extra = map[string]any{}
			}
			user.Extra[k] = v
		}
	}
}

// refreshSupport lets a provider report that it cannot refresh tokens (better-auth's optional refreshAccessToken).
type refreshSupport interface {
	SupportsRefresh() bool
}

// CanRefresh reports whether p supports refreshing access tokens.
func CanRefresh(p Provider) bool {
	if s, ok := p.(refreshSupport); ok {
		return s.SupportsRefresh()
	}
	return true
}
