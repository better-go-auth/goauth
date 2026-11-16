package providers

import (
	"context"
	"errors"
	"net/url"
	"time"
)

// GoogleOptions configures the Google provider.
type GoogleOptions struct {
	ProviderOptions
	// HD restricts sign-in to a Google Workspace hosted domain.
	HD string
}

type google struct {
	base
	hd string
}

// Google is better-auth's google provider (OIDC; user info read from the id_token).
func Google(opts GoogleOptions) Provider {
	return &google{base: base{ProviderOptions: opts.ProviderOptions, id: "google", name: "Google"}, hd: opts.HD}
}

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleJWKSURL  = "https://www.googleapis.com/oauth2/v3/certs"
)

func (p *google) CreateAuthorizationURL(_ context.Context, in AuthorizationURLInput) (*url.URL, error) {
	// Step 1: Google needs both client credentials and PKCE
	if p.ClientID == "" || p.ClientSecret == "" {
		return nil, ErrClientIDAndSecretRequired
	}
	if in.CodeVerifier == "" {
		return nil, errors.New("codeVerifier is required for Google")
	}
	// Step 2: build the URL with the default OIDC scopes
	return BuildAuthorizationURL(AuthURLParams{
		Endpoint:     pick(p.AuthorizationEndpoint, googleAuthURL),
		ClientID:     p.ClientID,
		State:        in.State,
		CodeVerifier: in.CodeVerifier,
		Scopes:       p.scopes([]string{"email", "profile", "openid"}, in.Scopes),
		RedirectURI:  pick(p.RedirectURI, in.RedirectURI),
		Prompt:       p.Prompt,
		AccessType:   p.AccessType,
		Display:      pick(in.Display, p.Display),
		LoginHint:    in.LoginHint,
		HD:           p.hd,
		Additional:   [][2]string{{"include_granted_scopes", "true"}},
	})
}

func (p *google) ValidateAuthorizationCode(ctx context.Context, in ValidateCodeInput) (*OAuth2Tokens, error) {
	return p.exchange(ctx, in, pick(p.TokenEndpoint, googleTokenURL), true)
}

func (p *google) RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuth2Tokens, error) {
	return p.refresh(ctx, refreshToken, pick(p.TokenEndpoint, googleTokenURL), nil)
}

func (p *google) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	return p.verifyIDToken(ctx, token, nonce, IDTokenCheck{
		JWKSEndpoint: pick(p.JWKSEndpoint, googleJWKSURL),
		Issuers:      []string{"https://accounts.google.com", "accounts.google.com"},
		Audiences:    p.audiences(),
		MaxAge:       time.Hour,
	}, func(claims map[string]any) bool {
		// hosted domain restriction
		return p.hd == "" || stringOf(claims["hd"]) == p.hd
	})
}

func (p *google) GetUserInfo(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error) {
	// Step 1: user override
	if p.ProviderOptions.GetUserInfo != nil {
		return p.ProviderOptions.GetUserInfo(ctx, tokens)
	}
	// Step 2: the profile is the (already verified / freshly issued) id_token
	if tokens.IDToken == "" {
		return nil, nil
	}
	profile, err := DecodeJWT(tokens.IDToken)
	if err != nil {
		return nil, nil
	}
	if p.hd != "" && stringOf(profile["hd"]) != p.hd {
		return nil, nil
	}
	// Step 3: normalize
	user := UserInfo{
		ID:            stringOf(profile["sub"]),
		Name:          stringOf(profile["name"]),
		Email:         stringOf(profile["email"]),
		Image:         stringOf(profile["picture"]),
		EmailVerified: boolOf(profile["email_verified"]),
	}
	p.applyProfileMap(&user, profile)
	return &UserInfoResult{User: user, Data: profile}, nil
}
