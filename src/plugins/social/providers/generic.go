package providers

import (
	"context"
	"errors"
	"net/url"
	"time"
)

// GenericOptions configures a generic OAuth2 / OpenID Connect provider (like better-auth's genericOAuth
// config). AuthorizationEndpoint and TokenEndpoint are required; the user comes from UserInfoEndpoint or,
// without one, from the id_token claims.
type GenericOptions struct {
	ProviderOptions
	// ProviderID is the id used on accounts and in /callback/{id} (required).
	ProviderID string
	// ProviderName is a display name (defaults to ProviderID).
	ProviderName string
	// DefaultScopes are requested unless DisableDefaultScope (default: openid email profile).
	DefaultScopes []string
	// DisablePKCE stops sending code_challenge / code_verifier.
	DisablePKCE bool
	// Authentication of the token endpoint: AuthPost (default) or AuthBasic.
	Authentication TokenAuth
	// Issuer pins the id_token "iss" claim (optional).
	Issuer string
	// IDTokenMaxAge limits id_token age for id_token sign-in (default 1h, negative = unlimited).
	IDTokenMaxAge time.Duration
	// ResponseType / ResponseMode override the authorization request parameters.
	ResponseType string
	ResponseMode string
	// AuthorizationParams are extra authorization URL parameters.
	AuthorizationParams map[string]string
	// TokenParams are extra token request parameters.
	TokenParams map[string]string
	// DisableIDTokenUserInfo always reads the user from UserInfoEndpoint, even when the id_token has sub + email.
	DisableIDTokenUserInfo bool
}

type generic struct {
	base
	opts GenericOptions
}

// Generic returns a configurable OAuth2/OIDC provider.
func Generic(opts GenericOptions) Provider {
	if opts.ProviderName == "" {
		opts.ProviderName = opts.ProviderID
	}
	if opts.DefaultScopes == nil {
		opts.DefaultScopes = []string{"openid", "email", "profile"}
	}
	if opts.IDTokenMaxAge == 0 {
		opts.IDTokenMaxAge = time.Hour
	}
	return &generic{base: base{ProviderOptions: opts.ProviderOptions, id: opts.ProviderID, name: opts.ProviderName}, opts: opts}
}

// SupportsIDToken reports whether id_token sign-in is possible (a JWKS URL or a custom verifier).
func (p *generic) SupportsIDToken() bool {
	return p.JWKSEndpoint != "" || p.ProviderOptions.VerifyIDToken != nil
}

func (p *generic) CreateAuthorizationURL(_ context.Context, in AuthorizationURLInput) (*url.URL, error) {
	// Step 1: endpoint and client are required
	if p.AuthorizationEndpoint == "" {
		return nil, errors.New("social: generic provider requires an authorization endpoint")
	}
	if p.ClientID == "" {
		return nil, ErrClientIDAndSecretRequired
	}
	// Step 2: PKCE unless disabled
	verifier := in.CodeVerifier
	if p.opts.DisablePKCE {
		verifier = ""
	}
	var extra [][2]string
	for k, v := range p.opts.AuthorizationParams {
		extra = append(extra, [2]string{k, v})
	}
	return BuildAuthorizationURL(AuthURLParams{
		Endpoint:     p.AuthorizationEndpoint,
		ClientID:     p.ClientID,
		State:        in.State,
		CodeVerifier: verifier,
		Scopes:       p.scopes(p.opts.DefaultScopes, in.Scopes),
		RedirectURI:  pick(p.RedirectURI, in.RedirectURI),
		Prompt:       p.Prompt,
		AccessType:   p.AccessType,
		Display:      pick(in.Display, p.Display),
		LoginHint:    in.LoginHint,
		ResponseType: p.opts.ResponseType,
		ResponseMode: p.opts.ResponseMode,
		Additional:   extra,
	})
}

func (p *generic) ValidateAuthorizationCode(ctx context.Context, in ValidateCodeInput) (*OAuth2Tokens, error) {
	verifier := in.CodeVerifier
	if p.opts.DisablePKCE {
		verifier = ""
	}
	return ExchangeCode(ctx, p.client(), CodeExchange{
		TokenEndpoint:  p.TokenEndpoint,
		Code:           in.Code,
		CodeVerifier:   verifier,
		RedirectURI:    pick(p.RedirectURI, in.RedirectURI),
		DeviceID:       in.DeviceID,
		ClientID:       p.ClientID,
		ClientSecret:   p.ClientSecret,
		Authentication: p.opts.Authentication,
		Extra:          p.opts.TokenParams,
	})
}

func (p *generic) RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuth2Tokens, error) {
	if p.ProviderOptions.RefreshAccessToken != nil {
		return p.ProviderOptions.RefreshAccessToken(ctx, refreshToken)
	}
	return Refresh(ctx, p.client(), RefreshRequest{
		TokenEndpoint:  p.TokenEndpoint,
		RefreshToken:   refreshToken,
		ClientID:       p.ClientID,
		ClientSecret:   p.ClientSecret,
		Authentication: p.opts.Authentication,
	})
}

func (p *generic) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	check := IDTokenCheck{JWKSEndpoint: p.JWKSEndpoint, Audiences: p.audiences()}
	if p.opts.Issuer != "" {
		check.Issuers = []string{p.opts.Issuer}
	}
	if p.opts.IDTokenMaxAge > 0 {
		check.MaxAge = p.opts.IDTokenMaxAge
	}
	return p.verifyIDToken(ctx, token, nonce, check, nil)
}

func (p *generic) GetUserInfo(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error) {
	// Step 1: user override
	if p.ProviderOptions.GetUserInfo != nil {
		return p.ProviderOptions.GetUserInfo(ctx, tokens)
	}
	// Step 2: the profile: id_token claims when they identify the user (sub + email, like better-auth's
	// genericOAuth), else the userinfo endpoint, else whatever the id_token holds
	var profile, claims map[string]any
	if tokens.IDToken != "" {
		claims, _ = DecodeJWT(tokens.IDToken)
		if claims != nil && !p.opts.DisableIDTokenUserInfo && stringOf(claims["sub"]) != "" && stringOf(claims["email"]) != "" {
			profile = claims
		}
	}
	if profile == nil && p.UserInfoEndpoint != "" && tokens.AccessToken != "" {
		if err := GetJSON(ctx, p.client(), p.UserInfoEndpoint, bearer(tokens.AccessToken), &profile); err != nil {
			return nil, nil
		}
	}
	if profile == nil {
		if claims == nil {
			return nil, nil
		}
		profile = claims
	}
	// Step 3: normalize the standard OIDC claims
	return ProfileToUserInfo(&p.ProviderOptions, profile), nil
}

// ProfileToUserInfo maps standard OIDC claims (sub, name, email, picture, email_verified) and then applies
// the provider's MapProfileToUser.
func ProfileToUserInfo(o *ProviderOptions, profile map[string]any) *UserInfoResult {
	user := UserInfo{
		ID:            profileString(profile, "sub", "id"),
		Name:          profileString(profile, "name", "preferred_username", "login"),
		Email:         stringOf(profile["email"]),
		Image:         profileString(profile, "picture", "image", "avatar_url"),
		EmailVerified: boolOf(profile["email_verified"]),
	}
	o.applyProfileMap(&user, profile)
	return &UserInfoResult{User: user, Data: profile}
}

// SupportsRefresh reports whether the provider can refresh tokens (a token endpoint or a custom refresher).
func (p *generic) SupportsRefresh() bool {
	return p.TokenEndpoint != "" || p.ProviderOptions.RefreshAccessToken != nil
}
