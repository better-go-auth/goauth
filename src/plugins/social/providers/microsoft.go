package providers

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MicrosoftOptions configures the Microsoft Entra ID provider.
type MicrosoftOptions struct {
	ProviderOptions
	// TenantID is "common" (default), "organizations", "consumers" or a tenant id.
	TenantID string
	// Authority defaults to https://login.microsoftonline.com.
	Authority string
	// ProfilePhotoSize of the Graph photo (default 48).
	ProfilePhotoSize int
	// DisableProfilePhoto skips the Graph photo lookup.
	DisableProfilePhoto bool
	// PhotoEndpoint overrides the Graph photo URL prefix (https://graph.microsoft.com/v1.0/me/photos).
	PhotoEndpoint string
}

type microsoft struct {
	base
	opts MicrosoftOptions
}

// Microsoft is better-auth's microsoft (Entra ID) provider.
func Microsoft(opts MicrosoftOptions) Provider {
	if opts.TenantID == "" {
		opts.TenantID = "common"
	}
	if opts.Authority == "" {
		opts.Authority = "https://login.microsoftonline.com"
	}
	return &microsoft{base: base{ProviderOptions: opts.ProviderOptions, id: "microsoft", name: "Microsoft EntraID"}, opts: opts}
}

func (p *microsoft) authURL() string {
	return pick(p.AuthorizationEndpoint, p.opts.Authority+"/"+p.opts.TenantID+"/oauth2/v2.0/authorize")
}
func (p *microsoft) tokenURL() string {
	return pick(p.TokenEndpoint, p.opts.Authority+"/"+p.opts.TenantID+"/oauth2/v2.0/token")
}
func (p *microsoft) defaultScopes() []string {
	return []string{"openid", "profile", "email", "User.Read", "offline_access"}
}

func (p *microsoft) CreateAuthorizationURL(_ context.Context, in AuthorizationURLInput) (*url.URL, error) {
	if p.ClientID == "" {
		return nil, ErrClientIDAndSecretRequired
	}
	return BuildAuthorizationURL(AuthURLParams{
		Endpoint:     p.authURL(),
		ClientID:     p.ClientID,
		State:        in.State,
		CodeVerifier: in.CodeVerifier,
		Scopes:       p.scopes(p.defaultScopes(), in.Scopes),
		RedirectURI:  pick(p.RedirectURI, in.RedirectURI),
		Prompt:       p.Prompt,
		LoginHint:    in.LoginHint,
	})
}

func (p *microsoft) ValidateAuthorizationCode(ctx context.Context, in ValidateCodeInput) (*OAuth2Tokens, error) {
	return p.exchange(ctx, in, p.tokenURL(), true)
}

func (p *microsoft) RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuth2Tokens, error) {
	scopes := p.scopes(p.defaultScopes(), nil)
	return p.refresh(ctx, refreshToken, p.tokenURL(), map[string]string{"scope": strings.Join(scopes, " ")})
}

func (p *microsoft) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	check := IDTokenCheck{
		JWKSEndpoint: pick(p.JWKSEndpoint, p.opts.Authority+"/"+p.opts.TenantID+"/discovery/v2.0/keys"),
		Audiences:    p.audiences(),
		MaxAge:       time.Hour,
	}
	// the issuer varies per tenant on the multi-tenant endpoints, so it is only pinned for a specific tenant
	if !slices.Contains([]string{"common", "organizations", "consumers"}, p.opts.TenantID) {
		check.Issuers = []string{p.opts.Authority + "/" + p.opts.TenantID + "/v2.0"}
	}
	return p.verifyIDToken(ctx, token, nonce, check, nil)
}

func (p *microsoft) GetUserInfo(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error) {
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
	// Step 3: optional Graph profile photo
	if !p.opts.DisableProfilePhoto && tokens.AccessToken != "" {
		size := p.opts.ProfilePhotoSize
		if size <= 0 {
			size = 48
		}
		s := strconv.Itoa(size)
		photoURL := pick(p.opts.PhotoEndpoint, "https://graph.microsoft.com/v1.0/me/photos") + "/" + s + "x" + s + "/$value"
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, photoURL, nil); err == nil {
			req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			if resp, err := p.client().Do(req); err == nil {
				if resp.StatusCode == http.StatusOK {
					if pic, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)); err == nil {
						profile["picture"] = "data:image/jpeg;base64, " + base64.StdEncoding.EncodeToString(pic)
					}
				}
				resp.Body.Close()
			}
		}
	}
	// Step 4: email verification from the optional claims
	email := stringOf(profile["email"])
	verified := false
	if v, ok := profile["email_verified"]; ok {
		verified = boolOf(v)
	} else if email != "" {
		verified = listContains(profile["verified_primary_email"], email) || listContains(profile["verified_secondary_email"], email)
	}
	user := UserInfo{
		ID:            stringOf(profile["sub"]),
		Name:          stringOf(profile["name"]),
		Email:         email,
		Image:         stringOf(profile["picture"]),
		EmailVerified: verified,
	}
	p.applyProfileMap(&user, profile)
	return &UserInfoResult{User: user, Data: profile}, nil
}

func listContains(v any, s string) bool {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if stringOf(e) == s {
				return true
			}
		}
	case string:
		return strings.Contains(x, s)
	}
	return false
}
