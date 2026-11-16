package providers

import (
	"context"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// DiscordOptions configures the Discord provider.
type DiscordOptions struct {
	ProviderOptions
	// Permissions is sent when the "bot" scope is requested.
	Permissions *int
}

type discord struct {
	base
	permissions *int
}

// Discord is better-auth's discord provider.
func Discord(opts DiscordOptions) Provider {
	return &discord{base: base{ProviderOptions: opts.ProviderOptions, id: "discord", name: "Discord"}, permissions: opts.Permissions}
}

const (
	discordAuthURL  = "https://discord.com/api/oauth2/authorize"
	discordTokenURL = "https://discord.com/api/oauth2/token"
	discordUserURL  = "https://discord.com/api/users/@me"
)

func (p *discord) CreateAuthorizationURL(_ context.Context, in AuthorizationURLInput) (*url.URL, error) {
	// Step 1: scopes (better-auth appends request scopes before configured ones for discord)
	var scopes []string
	if !p.DisableDefaultScope {
		scopes = append(scopes, "identify", "email")
	}
	scopes = append(scopes, in.Scopes...)
	scopes = append(scopes, p.Scope...)
	// Step 2: discord's hand-built URL (no PKCE)
	raw := fmt.Sprintf("%s?scope=%s&response_type=code&client_id=%s&redirect_uri=%s&state=%s&prompt=%s",
		pick(p.AuthorizationEndpoint, discordAuthURL), strings.Join(scopes, "+"), p.ClientID,
		url.QueryEscape(pick(p.RedirectURI, in.RedirectURI)), in.State, pick(p.Prompt, "none"))
	if slices.Contains(scopes, "bot") && p.permissions != nil {
		raw += "&permissions=" + strconv.Itoa(*p.permissions)
	}
	return url.Parse(raw)
}

func (p *discord) ValidateAuthorizationCode(ctx context.Context, in ValidateCodeInput) (*OAuth2Tokens, error) {
	return p.exchange(ctx, in, pick(p.TokenEndpoint, discordTokenURL), false)
}

func (p *discord) RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuth2Tokens, error) {
	return p.refresh(ctx, refreshToken, pick(p.TokenEndpoint, discordTokenURL), nil)
}

func (p *discord) GetUserInfo(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error) {
	// Step 1: user override
	if p.ProviderOptions.GetUserInfo != nil {
		return p.ProviderOptions.GetUserInfo(ctx, tokens)
	}
	// Step 2: the profile
	var profile map[string]any
	if err := GetJSON(ctx, p.client(), pick(p.UserInfoEndpoint, discordUserURL), bearer(tokens.AccessToken), &profile); err != nil {
		return nil, nil
	}
	// Step 3: avatar URL (default avatar when none is set)
	id := stringOf(profile["id"])
	if avatar := stringOf(profile["avatar"]); avatar == "" {
		var idx int64
		if disc := stringOf(profile["discriminator"]); disc == "0" || disc == "" {
			n, _ := new(big.Int).SetString(id, 10)
			if n != nil {
				idx = new(big.Int).Rsh(n, 22).Int64() % 6
			}
		} else {
			d, _ := strconv.Atoi(disc)
			idx = int64(d % 5)
		}
		profile["image_url"] = fmt.Sprintf("https://cdn.discordapp.com/embed/avatars/%d.png", idx)
	} else {
		format := "png"
		if strings.HasPrefix(avatar, "a_") {
			format = "gif"
		}
		profile["image_url"] = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.%s", id, avatar, format)
	}
	// Step 4: normalize
	user := UserInfo{
		ID:            id,
		Name:          profileString(profile, "global_name", "username"),
		Email:         stringOf(profile["email"]),
		Image:         stringOf(profile["image_url"]),
		EmailVerified: boolOf(profile["verified"]),
	}
	p.applyProfileMap(&user, profile)
	return &UserInfoResult{User: user, Data: profile}, nil
}
