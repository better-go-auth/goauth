package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	"crypto/subtle"
)

// AppleOptions configures the Apple provider.
type AppleOptions struct {
	ProviderOptions
	// AppBundleIdentifier is the id_token audience for native apps.
	AppBundleIdentifier string
	// Audience overrides the accepted id_token audiences.
	Audience []string
}

type apple struct {
	base
	opts AppleOptions
}

// Apple is better-auth's apple provider (form_post response, user info from the id_token).
func Apple(opts AppleOptions) Provider {
	return &apple{base: base{ProviderOptions: opts.ProviderOptions, id: "apple", name: "Apple"}, opts: opts}
}

const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
	appleJWKSURL  = "https://appleid.apple.com/auth/keys"
	appleIssuer   = "https://appleid.apple.com"
)

func (p *apple) CreateAuthorizationURL(_ context.Context, in AuthorizationURLInput) (*url.URL, error) {
	if p.ClientID == "" || p.ClientSecret == "" {
		return nil, ErrClientIDAndSecretRequired
	}
	return BuildAuthorizationURL(AuthURLParams{
		Endpoint:     pick(p.AuthorizationEndpoint, appleAuthURL),
		ClientID:     p.ClientID,
		State:        in.State,
		Scopes:       p.scopes([]string{"email", "name"}, in.Scopes),
		RedirectURI:  pick(p.RedirectURI, in.RedirectURI),
		ResponseMode: "form_post",
		ResponseType: "code id_token",
	})
}

func (p *apple) ValidateAuthorizationCode(ctx context.Context, in ValidateCodeInput) (*OAuth2Tokens, error) {
	return p.exchange(ctx, in, pick(p.TokenEndpoint, appleTokenURL), true)
}

func (p *apple) RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuth2Tokens, error) {
	return p.refresh(ctx, refreshToken, pick(p.TokenEndpoint, appleTokenURL), nil)
}

func (p *apple) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	// Step 1: audience: explicit list, then the bundle id, then the client id
	aud := p.opts.Audience
	if len(aud) == 0 && p.opts.AppBundleIdentifier != "" {
		aud = []string{p.opts.AppBundleIdentifier}
	}
	if len(aud) == 0 {
		aud = p.audiences()
	}
	// Step 2: verify; Apple may put sha256(nonce) in the token, so the nonce is checked here
	return p.verifyIDToken(ctx, token, "", IDTokenCheck{
		JWKSEndpoint: pick(p.JWKSEndpoint, appleJWKSURL),
		Issuers:      []string{appleIssuer},
		Audiences:    aud,
		MaxAge:       time.Hour,
	}, func(claims map[string]any) bool {
		if nonce == "" {
			return true
		}
		jwtNonce, ok := claims["nonce"].(string)
		if !ok {
			return false
		}
		sum := sha256.Sum256([]byte(nonce))
		return secureEqual(jwtNonce, nonce) || secureEqual(jwtNonce, hex.EncodeToString(sum[:]))
	})
}

// secureEqual compares nonces in constant time (crypto/subtle directly: this package must not import goauth
// packages that depend on config, because config.AuthConfig.SocialProviders references it).
func secureEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (p *apple) GetUserInfo(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error) {
	// Step 1: user override
	if p.ProviderOptions.GetUserInfo != nil {
		return p.ProviderOptions.GetUserInfo(ctx, tokens)
	}
	// Step 2: the profile is the id_token
	if tokens.IDToken == "" {
		return nil, nil
	}
	profile, err := DecodeJWT(tokens.IDToken)
	if err != nil {
		return nil, nil
	}
	// Step 3: Apple only sends the name once, in the `user` form field
	name := stringOf(profile["name"])
	if tokens.User != nil && tokens.User.Name != nil {
		name = strings.TrimSpace(tokens.User.Name.FirstName + " " + tokens.User.Name.LastName)
	}
	profile["name"] = name
	user := UserInfo{
		ID:            stringOf(profile["sub"]),
		Name:          name,
		Email:         stringOf(profile["email"]),
		EmailVerified: boolOf(profile["email_verified"]),
	}
	p.applyProfileMap(&user, profile)
	return &UserInfoResult{User: user, Data: profile}, nil
}
