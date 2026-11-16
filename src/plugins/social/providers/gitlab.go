package providers

import (
	"context"
	"net/url"
	"regexp"
	"strings"
)

// GitLabOptions configures the GitLab provider.
type GitLabOptions struct {
	ProviderOptions
	// Issuer is the GitLab instance URL (default https://gitlab.com).
	Issuer string
}

type gitlab struct {
	base
	authURL, tokenURL, userURL string
}

var doubleSlashes = regexp.MustCompile(`/{2,}`)

// cleanDoubleSlashes collapses "//" outside the scheme separator.
func cleanDoubleSlashes(s string) string {
	parts := strings.Split(s, "://")
	for i := range parts {
		parts[i] = doubleSlashes.ReplaceAllString(parts[i], "/")
	}
	return strings.Join(parts, "://")
}

// GitLab is better-auth's gitlab provider.
func GitLab(opts GitLabOptions) Provider {
	issuer := pick(opts.Issuer, "https://gitlab.com")
	return &gitlab{
		base:     base{ProviderOptions: opts.ProviderOptions, id: "gitlab", name: "Gitlab"},
		authURL:  pick(opts.AuthorizationEndpoint, cleanDoubleSlashes(issuer+"/oauth/authorize")),
		tokenURL: pick(opts.TokenEndpoint, cleanDoubleSlashes(issuer+"/oauth/token")),
		userURL:  pick(opts.UserInfoEndpoint, cleanDoubleSlashes(issuer+"/api/v4/user")),
	}
}

func (p *gitlab) CreateAuthorizationURL(_ context.Context, in AuthorizationURLInput) (*url.URL, error) {
	return BuildAuthorizationURL(AuthURLParams{
		Endpoint:     p.authURL,
		ClientID:     p.ClientID,
		State:        in.State,
		CodeVerifier: in.CodeVerifier,
		Scopes:       p.scopes([]string{"read_user"}, in.Scopes),
		RedirectURI:  pick(p.RedirectURI, in.RedirectURI),
		LoginHint:    in.LoginHint,
	})
}

func (p *gitlab) ValidateAuthorizationCode(ctx context.Context, in ValidateCodeInput) (*OAuth2Tokens, error) {
	return p.exchange(ctx, in, p.tokenURL, true)
}

func (p *gitlab) RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuth2Tokens, error) {
	return p.refresh(ctx, refreshToken, p.tokenURL, nil)
}

func (p *gitlab) GetUserInfo(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error) {
	// Step 1: user override
	if p.ProviderOptions.GetUserInfo != nil {
		return p.ProviderOptions.GetUserInfo(ctx, tokens)
	}
	// Step 2: the profile; blocked or locked users cannot sign in
	var profile map[string]any
	if err := GetJSON(ctx, p.client(), p.userURL, bearer(tokens.AccessToken), &profile); err != nil {
		return nil, nil
	}
	if stringOf(profile["state"]) != "active" || boolOf(profile["locked"]) {
		return nil, nil
	}
	// Step 3: normalize
	name := stringOf(profile["name"])
	if _, ok := profile["name"]; !ok || profile["name"] == nil {
		name = stringOf(profile["username"])
	}
	user := UserInfo{
		ID:            stringOf(profile["id"]),
		Name:          name,
		Email:         stringOf(profile["email"]),
		Image:         stringOf(profile["avatar_url"]),
		EmailVerified: boolOf(profile["email_verified"]),
	}
	p.applyProfileMap(&user, profile)
	return &UserInfoResult{User: user, Data: profile}, nil
}
