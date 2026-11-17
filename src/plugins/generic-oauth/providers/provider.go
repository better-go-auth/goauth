// Package providers adapts generic-oauth provider configs to the social plugin's provider abstraction
// (social/providers.Provider) and ships better-auth's provider presets (auth0, okta, keycloak, ...).
//
// The adapter owns what is specific to a generic provider: OIDC discovery (cached), the authorization URL
// parameters, the code exchange (getToken override, basic/post authentication, extra headers and params)
// and better-auth's generic user info lookup (id_token claims, then the userinfo endpoint).
package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	socialproviders "github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// Discovery is the subset of an OpenID Connect discovery document the plugin uses.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// ErrNoAuthorizationURL is returned when neither AuthorizationURL nor discovery yields an endpoint.
var ErrNoAuthorizationURL = errors.New("generic-oauth: invalid OAuth configuration: no authorization URL")

// ErrNoTokenURL is returned when neither TokenURL nor discovery yields a token endpoint.
var ErrNoTokenURL = errors.New("generic-oauth: invalid OAuth configuration: token URL not found")

var defaultClient = &http.Client{Timeout: 10 * time.Second}

// Provider is one generic-oauth provider. It implements social/providers.Provider, so it can also be passed
// to the social plugin (then /sign-in/social, /get-access-token, /refresh-token and /account-info work with it).
type Provider struct {
	cfg      config.ProviderConfig
	cacheTTL time.Duration
	opts     socialproviders.ProviderOptions

	mu        sync.Mutex
	doc       *Discovery
	fetchedAt time.Time
}

var _ socialproviders.Provider = (*Provider)(nil)

// New adapts cfg. cacheTTL is the discovery cache lifetime (0 disables caching).
func New(cfg config.ProviderConfig, cacheTTL time.Duration) *Provider {
	return &Provider{
		cfg:      cfg,
		cacheTTL: cacheTTL,
		opts: socialproviders.ProviderOptions{
			ClientID:                 cfg.ClientID,
			ClientSecret:             cfg.ClientSecret,
			RedirectURI:              cfg.RedirectURI,
			Prompt:                   cfg.Prompt,
			AccessType:               cfg.AccessType,
			DisableSignUp:            cfg.DisableSignUp,
			DisableImplicitSignUp:    cfg.DisableImplicitSignUp,
			OverrideUserInfoOnSignIn: cfg.OverrideUserInfo,
			// generic providers have no id_token verifier (better-auth's adapter has no verifyIdToken)
			DisableIDTokenSignIn: true,
			HTTPClient:           cfg.HTTPClient,
		},
	}
}

// Config returns the provider configuration.
func (p *Provider) Config() config.ProviderConfig { return p.cfg }

// ID is the provider id.
func (p *Provider) ID() string { return p.cfg.ProviderID }

// Name is the provider id (better-auth uses the id as name).
func (p *Provider) Name() string { return p.cfg.ProviderID }

// Options returns the sign-up and user-info policies in the social plugin's format.
func (p *Provider) Options() *socialproviders.ProviderOptions { return &p.opts }

func (p *Provider) client() *http.Client {
	if p.cfg.HTTPClient != nil {
		return p.cfg.HTTPClient
	}
	return defaultClient
}

// ─── Discovery ───────────────────────────────────────────────────────────────

// Discover returns the provider's discovery document, or nil when the provider has no DiscoveryURL or the
// document cannot be fetched (better-auth then falls back to the configured endpoints).
func (p *Provider) Discover(ctx context.Context) *Discovery {
	// Step 1: no discovery configured
	if p.cfg.DiscoveryURL == "" {
		return nil
	}
	// Step 2: a cached document that is still fresh
	p.mu.Lock()
	if p.doc != nil && p.cacheTTL > 0 && time.Since(p.fetchedAt) < p.cacheTTL {
		doc := p.doc
		p.mu.Unlock()
		return doc
	}
	p.mu.Unlock()
	// Step 3: fetch (with discoveryHeaders); failures are not cached
	var doc Discovery
	if err := socialproviders.GetJSON(ctx, p.client(), p.cfg.DiscoveryURL, p.cfg.DiscoveryHeaders, &doc); err != nil {
		return nil
	}
	// Step 4: remember it
	if p.cacheTTL > 0 {
		p.mu.Lock()
		p.doc, p.fetchedAt = &doc, time.Now()
		p.mu.Unlock()
	}
	return &doc
}

// ─── Authorization URL ───────────────────────────────────────────────────────

// AuthURLRequest are the per-request parameters of BuildAuthorizationURL.
type AuthURLRequest struct {
	State        string
	CodeVerifier string
	RedirectURI  string
	Scopes       []string
	Prompt       string
	AccessType   string
	ResponseType string
	ResponseMode string
	LoginHint    string
	// Additional are appended last (sorted by key so the URL is deterministic).
	Additional map[string]string
}

// BuildAuthorizationURL is better-auth's createAuthorizationURL for this provider and endpoint. The PKCE
// challenge is only sent when the provider has PKCE enabled; ProviderConfig.RedirectURI wins over r.RedirectURI.
func (p *Provider) BuildAuthorizationURL(endpoint string, r AuthURLRequest) (*url.URL, error) {
	// Step 1: PKCE only when enabled
	verifier := ""
	if p.cfg.PKCE {
		verifier = r.CodeVerifier
	}
	// Step 2: scopes are always sent (an empty list gives scope=)
	scopes := r.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	// Step 3: the extra parameters in a stable order
	keys := make([]string, 0, len(r.Additional))
	for k := range r.Additional {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	extra := make([][2]string, 0, len(keys))
	for _, k := range keys {
		extra = append(extra, [2]string{k, r.Additional[k]})
	}
	redirectURI := r.RedirectURI
	if p.cfg.RedirectURI != "" {
		redirectURI = p.cfg.RedirectURI
	}
	return socialproviders.BuildAuthorizationURL(socialproviders.AuthURLParams{
		Endpoint:     endpoint,
		ClientID:     p.cfg.ClientID,
		State:        r.State,
		CodeVerifier: verifier,
		Scopes:       scopes,
		RedirectURI:  redirectURI,
		Prompt:       r.Prompt,
		AccessType:   r.AccessType,
		LoginHint:    r.LoginHint,
		ResponseType: r.ResponseType,
		ResponseMode: r.ResponseMode,
		Additional:   extra,
	})
}

// AuthorizationParams merges AuthorizationURLParams and AuthorizationURLParamsFunc (the function wins).
func (p *Provider) AuthorizationParams(ctx context.Context) map[string]string {
	return mergeParams(ctx, p.cfg.AuthorizationURLParams, p.cfg.AuthorizationURLParamsFunc)
}

// TokenParams merges TokenURLParams and TokenURLParamsFunc (the function wins).
func (p *Provider) TokenParams(ctx context.Context) map[string]string {
	return mergeParams(ctx, p.cfg.TokenURLParams, p.cfg.TokenURLParamsFunc)
}

func mergeParams(ctx context.Context, static map[string]string, fn func(context.Context) map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range static {
		out[k] = v
	}
	if fn != nil {
		for k, v := range fn(ctx) {
			out[k] = v
		}
	}
	return out
}

// CreateAuthorizationURL implements social/providers.Provider (used when the provider is mounted on the social
// plugin): the configured authorization URL, else discovery; request scopes are added to the configured ones.
func (p *Provider) CreateAuthorizationURL(ctx context.Context, in socialproviders.AuthorizationURLInput) (*url.URL, error) {
	// Step 1: the endpoint
	endpoint := p.cfg.AuthorizationURL
	if endpoint == "" {
		if doc := p.Discover(ctx); doc != nil {
			endpoint = doc.AuthorizationEndpoint
		}
	}
	if endpoint == "" {
		return nil, ErrNoAuthorizationURL
	}
	// Step 2: the URL
	return p.BuildAuthorizationURL(endpoint, AuthURLRequest{
		State:        in.State,
		CodeVerifier: in.CodeVerifier,
		RedirectURI:  in.RedirectURI,
		Scopes:       append(append([]string{}, in.Scopes...), p.cfg.Scopes...),
		Prompt:       p.cfg.Prompt,
		AccessType:   p.cfg.AccessType,
		ResponseType: p.cfg.ResponseType,
		ResponseMode: p.cfg.ResponseMode,
		LoginHint:    in.LoginHint,
		Additional:   p.AuthorizationParams(ctx),
	})
}

// ─── Tokens ──────────────────────────────────────────────────────────────────

// ExchangeRequest are the parameters of ExchangeCode.
type ExchangeRequest struct {
	// TokenURL is the resolved token endpoint (ignored when GetToken is configured).
	TokenURL     string
	Code         string
	CodeVerifier string
	RedirectURI  string
	// Extra are additional token request parameters (tokenUrlParams).
	Extra map[string]string
}

// ExchangeCode trades an authorization code for tokens: GetToken when configured, else the token endpoint
// with the configured authentication and headers. AccessTokenExpiresIn fills a missing expiry.
func (p *Provider) ExchangeCode(ctx context.Context, r ExchangeRequest) (*socialproviders.OAuth2Tokens, error) {
	// Step 1: PKCE verifier only when enabled
	verifier := ""
	if p.cfg.PKCE {
		verifier = r.CodeVerifier
	}
	// Step 2: custom exchange
	var (
		tokens *socialproviders.OAuth2Tokens
		err    error
	)
	if p.cfg.GetToken != nil {
		tokens, err = p.cfg.GetToken(ctx, config.GetTokenInput{Code: r.Code, RedirectURI: r.RedirectURI, CodeVerifier: verifier})
	} else {
		// Step 3: standard authorization_code grant
		if r.TokenURL == "" {
			return nil, ErrNoTokenURL
		}
		redirectURI := r.RedirectURI
		if p.cfg.RedirectURI != "" {
			redirectURI = p.cfg.RedirectURI
		}
		tokens, err = socialproviders.ExchangeCode(ctx, p.client(), socialproviders.CodeExchange{
			TokenEndpoint:  r.TokenURL,
			Code:           r.Code,
			CodeVerifier:   verifier,
			RedirectURI:    redirectURI,
			ClientID:       p.cfg.ClientID,
			ClientSecret:   p.cfg.ClientSecret,
			Authentication: p.cfg.Authentication,
			Extra:          r.Extra,
			Headers:        p.cfg.AuthorizationHeaders,
		})
	}
	if err != nil {
		return nil, err
	}
	if tokens == nil {
		return nil, errors.New("generic-oauth: no tokens")
	}
	// Step 4: default expiry
	p.applyDefaultExpiry(tokens)
	return tokens, nil
}

// applyDefaultExpiry is better-auth's applyDefaultAccessTokenExpiry.
func (p *Provider) applyDefaultExpiry(t *socialproviders.OAuth2Tokens) {
	if t.AccessTokenExpiresAt == nil && p.cfg.AccessTokenExpiresIn > 0 {
		at := time.Now().Add(p.cfg.AccessTokenExpiresIn)
		t.AccessTokenExpiresAt = &at
	}
}

// tokenURL is the token endpoint: discovery first (like better-auth), else TokenURL.
func (p *Provider) tokenURL(ctx context.Context) string {
	if doc := p.Discover(ctx); doc != nil && doc.TokenEndpoint != "" {
		return doc.TokenEndpoint
	}
	return p.cfg.TokenURL
}

// ValidateAuthorizationCode implements social/providers.Provider.
func (p *Provider) ValidateAuthorizationCode(ctx context.Context, in socialproviders.ValidateCodeInput) (*socialproviders.OAuth2Tokens, error) {
	return p.ExchangeCode(ctx, ExchangeRequest{
		TokenURL:     p.tokenURL(ctx),
		Code:         in.Code,
		CodeVerifier: in.CodeVerifier,
		RedirectURI:  in.RedirectURI,
		Extra:        p.TokenParams(ctx),
	})
}

// RefreshAccessToken implements social/providers.Provider (better-auth's generic refreshAccessToken).
func (p *Provider) RefreshAccessToken(ctx context.Context, refreshToken string) (*socialproviders.OAuth2Tokens, error) {
	// Step 1: the token endpoint
	endpoint := p.tokenURL(ctx)
	if endpoint == "" {
		return nil, ErrNoTokenURL
	}
	// Step 2: refresh_token grant
	tokens, err := socialproviders.Refresh(ctx, p.client(), socialproviders.RefreshRequest{
		TokenEndpoint:  endpoint,
		RefreshToken:   refreshToken,
		ClientID:       p.cfg.ClientID,
		ClientSecret:   p.cfg.ClientSecret,
		Authentication: p.cfg.Authentication,
	})
	if err != nil {
		return nil, err
	}
	p.applyDefaultExpiry(tokens)
	return tokens, nil
}

// SupportsRefresh reports whether a token endpoint is configured (or discoverable).
func (p *Provider) SupportsRefresh() bool {
	return p.cfg.TokenURL != "" || p.cfg.DiscoveryURL != ""
}

// ─── User info ───────────────────────────────────────────────────────────────

// FetchProfile is better-auth's generic getUserInfo (or the GetUserInfo override): the id_token claims when
// they carry sub and email, else the userinfo endpoint. nil means the user could not be resolved.
func (p *Provider) FetchProfile(ctx context.Context, tokens socialproviders.OAuth2Tokens, userInfoURL string) map[string]any {
	// Step 1: the override
	if p.cfg.GetUserInfo != nil {
		profile, err := p.cfg.GetUserInfo(ctx, tokens)
		if err != nil {
			return nil
		}
		return profile
	}
	return DefaultProfile(ctx, p.client(), tokens, userInfoURL)
}

// DefaultProfile is better-auth's generic getUserInfo.
func DefaultProfile(ctx context.Context, client *http.Client, tokens socialproviders.OAuth2Tokens, userInfoURL string) map[string]any {
	// Step 1: id_token claims identifying the user
	if tokens.IDToken != "" {
		if claims, err := socialproviders.DecodeJWT(tokens.IDToken); err == nil && claims != nil {
			if StringOf(claims["sub"]) != "" && StringOf(claims["email"]) != "" {
				out := map[string]any{"id": claims["sub"], "emailVerified": claims["email_verified"], "image": claims["picture"]}
				for k, v := range claims {
					out[k] = v
				}
				return out
			}
		}
	}
	// Step 2: the userinfo endpoint
	if userInfoURL == "" {
		return nil
	}
	if client == nil {
		client = defaultClient
	}
	var data map[string]any
	if err := socialproviders.GetJSON(ctx, client, userInfoURL, map[string]string{"Authorization": "Bearer " + tokens.AccessToken}, &data); err != nil {
		return nil
	}
	// Step 3: the subject is sub, else id
	subject := data["sub"]
	if subject == nil {
		subject = data["id"]
	}
	if StringOf(subject) == "" {
		return nil
	}
	verified := data["email_verified"]
	if verified == nil {
		verified = false
	}
	out := map[string]any{"id": subject, "emailVerified": verified, "email": data["email"], "image": data["picture"], "name": data["name"]}
	for k, v := range data {
		out[k] = v
	}
	return out
}

// userInfoURL is the userinfo endpoint for the social adapter: UserInfoURL, else discovery.
func (p *Provider) userInfoURL(ctx context.Context) string {
	if p.cfg.UserInfoURL != "" {
		return p.cfg.UserInfoURL
	}
	if doc := p.Discover(ctx); doc != nil {
		return doc.UserInfoEndpoint
	}
	return ""
}

// GetUserInfo implements social/providers.Provider (better-auth's adapter getUserInfo:
// {id, email, emailVerified, image, name, ...mapProfileToUser(profile)}).
func (p *Provider) GetUserInfo(ctx context.Context, tokens socialproviders.UserInfoInput) (*socialproviders.UserInfoResult, error) {
	// Step 1: the profile
	profile := p.FetchProfile(ctx, tokens.OAuth2Tokens, p.userInfoURL(ctx))
	if profile == nil {
		return nil, nil
	}
	// Step 2: the standard fields, then the mapped ones
	user := socialproviders.UserInfo{
		ID:            StringOf(profile["id"]),
		Name:          StringOf(profile["name"]),
		Email:         StringOf(profile["email"]),
		Image:         StringOf(profile["image"]),
		EmailVerified: BoolOf(profile["emailVerified"]),
	}
	if p.cfg.MapProfileToUser != nil {
		socialproviders.ApplyUserMap(&user, p.cfg.MapProfileToUser(profile))
	}
	return &socialproviders.UserInfoResult{User: user, Data: profile}, nil
}

// ─── Value helpers ───────────────────────────────────────────────────────────

// StringOf converts a JSON value to a string ("" for nil).
func StringOf(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		return fmt.Sprint(x)
	}
}

// BoolOf converts a JSON value to a bool (true or "true").
func BoolOf(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	default:
		return false
	}
}
