package providers

import (
	"context"
	"net/url"
	"slices"
	"strings"
)

// FacebookOptions configures the Facebook provider.
type FacebookOptions struct {
	ProviderOptions
	// Fields are extra Graph /me fields to request.
	Fields []string
	// ConfigID is Facebook Login for Business's config_id.
	ConfigID string
	// GraphEndpoint overrides https://graph.facebook.com (used for /me and /debug_token).
	GraphEndpoint string
	// Issuer of limited-login id tokens (default https://www.facebook.com).
	Issuer string
}

type facebook struct {
	base
	opts FacebookOptions
}

// Facebook is better-auth's facebook provider.
func Facebook(opts FacebookOptions) Provider {
	return &facebook{base: base{ProviderOptions: opts.ProviderOptions, id: "facebook", name: "Facebook"}, opts: opts}
}

func (p *facebook) graph() string {
	return strings.TrimRight(pick(p.opts.GraphEndpoint, "https://graph.facebook.com"), "/")
}
func (p *facebook) tokenURL() string {
	return pick(p.TokenEndpoint, p.graph()+"/v24.0/oauth/access_token")
}

func (p *facebook) CreateAuthorizationURL(_ context.Context, in AuthorizationURLInput) (*url.URL, error) {
	if p.ClientID == "" || p.ClientSecret == "" {
		return nil, ErrClientIDAndSecretRequired
	}
	var extra [][2]string
	if p.opts.ConfigID != "" {
		extra = append(extra, [2]string{"config_id", p.opts.ConfigID})
	}
	return BuildAuthorizationURL(AuthURLParams{
		Endpoint:    pick(p.AuthorizationEndpoint, "https://www.facebook.com/v24.0/dialog/oauth"),
		ClientID:    p.ClientID,
		State:       in.State,
		Scopes:      p.scopes([]string{"email", "public_profile"}, in.Scopes),
		RedirectURI: pick(p.RedirectURI, in.RedirectURI),
		LoginHint:   in.LoginHint,
		Additional:  extra,
	})
}

func (p *facebook) ValidateAuthorizationCode(ctx context.Context, in ValidateCodeInput) (*OAuth2Tokens, error) {
	return p.exchange(ctx, in, p.tokenURL(), false)
}

func (p *facebook) RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuth2Tokens, error) {
	return p.refresh(ctx, refreshToken, p.tokenURL(), nil)
}

// verifyAccessToken checks an opaque access token with /debug_token: it must be valid, issued to this app and
// tied to a user. It returns the token's user id ("" when invalid).
func (p *facebook) verifyAccessToken(ctx context.Context, token string) string {
	if p.ClientID == "" || p.ClientSecret == "" {
		return ""
	}
	q := url.Values{}
	q.Set("input_token", token)
	q.Set("access_token", p.ClientID+"|"+p.ClientSecret)
	var out struct {
		Data *struct {
			IsValid bool   `json:"is_valid"`
			AppID   string `json:"app_id"`
			UserID  string `json:"user_id"`
		} `json:"data"`
	}
	if err := GetJSON(ctx, p.client(), p.graph()+"/debug_token?"+q.Encode(), nil, &out); err != nil || out.Data == nil {
		return ""
	}
	if !out.Data.IsValid || out.Data.AppID == "" || out.Data.AppID != p.ClientID || out.Data.UserID == "" {
		return ""
	}
	return out.Data.UserID
}

func (p *facebook) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	if p.DisableIDTokenSignIn {
		return false, nil
	}
	if p.ProviderOptions.VerifyIDToken != nil {
		return p.ProviderOptions.VerifyIDToken(ctx, token, nonce)
	}
	// limited login: a JWT signed by Facebook
	if len(strings.Split(token, ".")) == 3 {
		return p.verifyIDToken(ctx, token, nonce, IDTokenCheck{
			JWKSEndpoint: pick(p.JWKSEndpoint, "https://limited.facebook.com/.well-known/oauth/openid/jwks/"),
			Issuers:      []string{pick(p.opts.Issuer, "https://www.facebook.com")},
			Audiences:    p.audiences(),
			Algorithms:   []string{"RS256"},
		}, nil)
	}
	// classic login: an opaque access token checked with /debug_token
	return p.verifyAccessToken(ctx, token) != "", nil
}

func (p *facebook) GetUserInfo(ctx context.Context, tokens UserInfoInput) (*UserInfoResult, error) {
	// Step 1: user override
	if p.ProviderOptions.GetUserInfo != nil {
		return p.ProviderOptions.GetUserInfo(ctx, tokens)
	}
	// Step 2: limited-login id token
	if tokens.IDToken != "" && len(strings.Split(tokens.IDToken, ".")) == 3 {
		profile, err := DecodeJWT(tokens.IDToken)
		if err != nil {
			return nil, nil
		}
		user := UserInfo{ID: stringOf(profile["sub"]), Name: stringOf(profile["name"]), Email: stringOf(profile["email"]), Image: stringOf(profile["picture"])}
		mapped := map[string]any{"id": user.ID, "name": user.Name, "email": user.Email, "picture": profile["picture"], "email_verified": false}
		p.applyProfileMap(&user, mapped)
		return &UserInfoResult{User: user, Data: profile}, nil
	}
	// Step 3: the access token must belong to this app
	if tokens.AccessToken == "" {
		return nil, nil
	}
	tokenUserID := p.verifyAccessToken(ctx, tokens.AccessToken)
	if tokenUserID == "" {
		return nil, nil
	}
	// Step 4: Graph /me
	fields := append([]string{"id", "name", "email", "picture"}, p.opts.Fields...)
	fields = slices.Compact(fields)
	var profile map[string]any
	if err := GetJSON(ctx, p.client(), pick(p.UserInfoEndpoint, p.graph()+"/me")+"?fields="+strings.Join(fields, ","), bearer(tokens.AccessToken), &profile); err != nil {
		return nil, nil
	}
	if stringOf(profile["id"]) != tokenUserID {
		return nil, nil
	}
	image := ""
	if pic, ok := profile["picture"].(map[string]any); ok {
		if data, ok := pic["data"].(map[string]any); ok {
			image = stringOf(data["url"])
		}
	}
	user := UserInfo{
		ID:            stringOf(profile["id"]),
		Name:          stringOf(profile["name"]),
		Email:         stringOf(profile["email"]),
		Image:         image,
		EmailVerified: boolOf(profile["email_verified"]),
	}
	p.applyProfileMap(&user, profile)
	return &UserInfoResult{User: user, Data: profile}, nil
}
