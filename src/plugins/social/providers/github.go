package providers

import (
	"context"
	"net/url"
)

// GitHubOptions configures the GitHub provider.
type GitHubOptions struct {
	ProviderOptions
	// EmailsEndpoint overrides https://api.github.com/user/emails.
	EmailsEndpoint string
}

type github struct {
	base
	emailsEndpoint string
}

// GitHub is better-auth's github provider (profile from /user, email from /user/emails).
func GitHub(opts GitHubOptions) Provider {
	return &github{base: base{ProviderOptions: opts.ProviderOptions, id: "github", name: "GitHub"}, emailsEndpoint: opts.EmailsEndpoint}
}

const (
	githubAuthURL   = "https://github.com/login/oauth/authorize"
	githubTokenURL  = "https://github.com/login/oauth/access_token"
	githubUserURL   = "https://api.github.com/user"
	githubEmailsURL = "https://api.github.com/user/emails"
)

func (p *github) CreateAuthorizationURL(_ context.Context, in AuthorizationURLInput) (*url.URL, error) {
	return BuildAuthorizationURL(AuthURLParams{
		Endpoint:     pick(p.AuthorizationEndpoint, githubAuthURL),
		ClientID:     p.ClientID,
		State:        in.State,
		CodeVerifier: in.CodeVerifier,
		Scopes:       p.scopes([]string{"read:user", "user:email"}, in.Scopes),
		RedirectURI:  pick(p.RedirectURI, in.RedirectURI),
		LoginHint:    in.LoginHint,
		Prompt:       p.Prompt,
	})
}

func (p *github) ValidateAuthorizationCode(ctx context.Context, in ValidateCodeInput) (*OAuth2Tokens, error) {
	// GitHub answers 200 {"error": ...} for bad codes: treat it as an invalid code (nil tokens)
	tokens, err := p.exchange(ctx, in, pick(p.TokenEndpoint, githubTokenURL), true)
	if err != nil {
		return nil, nil
	}
	if _, bad := tokens.Raw["error"]; bad {
		return nil, nil
	}
	return tokens, nil
}

func (p *github) RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuth2Tokens, error) {
	return p.refresh(ctx, refreshToken, pick(p.TokenEndpoint, githubTokenURL), nil)
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (p *github) GetUserInfo(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error) {
	// Step 1: user override
	if p.ProviderOptions.GetUserInfo != nil {
		return p.ProviderOptions.GetUserInfo(ctx, tokens)
	}
	// Step 2: the profile
	headers := bearer(tokens.AccessToken)
	headers["User-Agent"] = "better-auth"
	var profile map[string]any
	if err := GetJSON(ctx, p.client(), pick(p.UserInfoEndpoint, githubUserURL), headers, &profile); err != nil {
		return nil, nil
	}
	// Step 3: the email list (primary email when the profile hides it, and its verification state)
	var emails []githubEmail
	_ = GetJSON(ctx, p.client(), pick(p.emailsEndpoint, githubEmailsURL), headers, &emails)
	if stringOf(profile["email"]) == "" && len(emails) > 0 {
		chosen := emails[0]
		for _, e := range emails {
			if e.Primary {
				chosen = e
				break
			}
		}
		profile["email"] = chosen.Email
	}
	verified := false
	for _, e := range emails {
		if e.Email == stringOf(profile["email"]) {
			verified = e.Verified
			break
		}
	}
	// Step 4: normalize
	user := UserInfo{
		ID:            stringOf(profile["id"]),
		Name:          profileString(profile, "name", "login"),
		Email:         stringOf(profile["email"]),
		Image:         stringOf(profile["avatar_url"]),
		EmailVerified: verified,
	}
	p.applyProfileMap(&user, profile)
	return &UserInfoResult{User: user, Data: profile}, nil
}
