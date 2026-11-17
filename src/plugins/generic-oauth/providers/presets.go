package providers

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	socialproviders "github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// PresetOptions are the options shared by better-auth's generic-oauth provider helpers.
type PresetOptions struct {
	ClientID     string
	ClientSecret string
	// Scopes replace the preset's default scopes.
	Scopes                []string
	RedirectURI           string
	PKCE                  bool
	DisableImplicitSignUp bool
	DisableSignUp         bool
	OverrideUserInfo      bool
	// HTTPClient is used by the preset's user info lookup and the token requests.
	HTTPClient *http.Client
}

// apply copies the shared options onto cfg (scopes default to defaults).
func (o PresetOptions) apply(cfg config.ProviderConfig, defaults []string) config.ProviderConfig {
	cfg.ClientID = o.ClientID
	cfg.ClientSecret = o.ClientSecret
	cfg.Scopes = o.Scopes
	if cfg.Scopes == nil {
		cfg.Scopes = defaults
	}
	cfg.RedirectURI = o.RedirectURI
	cfg.PKCE = o.PKCE
	cfg.DisableImplicitSignUp = o.DisableImplicitSignUp
	cfg.DisableSignUp = o.DisableSignUp
	cfg.OverrideUserInfo = o.OverrideUserInfo
	cfg.HTTPClient = o.HTTPClient
	return cfg
}

func (o PresetOptions) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return defaultClient
}

var oidcScopes = []string{"openid", "profile", "email"}

// fetchJSON GETs endpoint with a bearer token; nil on any error.
func fetchJSON(ctx context.Context, client *http.Client, endpoint, accessToken string) map[string]any {
	var out map[string]any
	headers := map[string]string{}
	if accessToken != "" {
		headers["Authorization"] = "Bearer " + accessToken
	}
	if err := socialproviders.GetJSON(ctx, client, endpoint, headers, &out); err != nil {
		return nil
	}
	return out
}

func firstNonNil(vs ...any) any {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}

var schemeRe = regexp.MustCompile(`^https?://`)

// ─── Auth0 ───────────────────────────────────────────────────────────────────

// Auth0Options configures Auth0.
type Auth0Options struct {
	PresetOptions
	// Domain is the Auth0 domain (e.g. "dev-xxx.eu.auth0.com"; a scheme is stripped).
	Domain string
}

// Auth0 is better-auth's auth0() helper (OIDC discovery on the tenant domain).
func Auth0(o Auth0Options) config.ProviderConfig {
	return o.apply(config.ProviderConfig{
		ProviderID:   "auth0",
		DiscoveryURL: "https://" + schemeRe.ReplaceAllString(o.Domain, "") + "/.well-known/openid-configuration",
	}, oidcScopes)
}

// ─── Keycloak / Okta ─────────────────────────────────────────────────────────

// IssuerOptions configures the issuer based presets (Keycloak, Okta).
type IssuerOptions struct {
	PresetOptions
	// Issuer is the realm / authorization server URL (e.g. "https://kc.example.com/realms/main").
	Issuer string
}

// Keycloak is better-auth's keycloak() helper.
func Keycloak(o IssuerOptions) config.ProviderConfig {
	return o.apply(config.ProviderConfig{
		ProviderID:   "keycloak",
		DiscoveryURL: strings.TrimSuffix(o.Issuer, "/") + "/.well-known/openid-configuration",
	}, oidcScopes)
}

// Okta is better-auth's okta() helper.
func Okta(o IssuerOptions) config.ProviderConfig {
	return o.apply(config.ProviderConfig{
		ProviderID:   "okta",
		DiscoveryURL: strings.TrimSuffix(o.Issuer, "/") + "/.well-known/openid-configuration",
	}, oidcScopes)
}

// ─── Microsoft Entra ID ──────────────────────────────────────────────────────

// MicrosoftEntraIDOptions configures Microsoft Entra ID.
type MicrosoftEntraIDOptions struct {
	PresetOptions
	// TenantID is the directory (tenant) id, or "common" / "organizations" / "consumers".
	TenantID string
}

// MicrosoftEntraIDUserInfoURL is the Microsoft Graph OIDC userinfo endpoint.
const MicrosoftEntraIDUserInfoURL = "https://graph.microsoft.com/oidc/userinfo"

// MicrosoftEntraID is better-auth's microsoftEntraId() helper.
func MicrosoftEntraID(o MicrosoftEntraIDOptions) config.ProviderConfig {
	cfg := o.apply(config.ProviderConfig{
		ProviderID:       "microsoft-entra-id",
		AuthorizationURL: "https://login.microsoftonline.com/" + o.TenantID + "/oauth2/v2.0/authorize",
		TokenURL:         "https://login.microsoftonline.com/" + o.TenantID + "/oauth2/v2.0/token",
		UserInfoURL:      MicrosoftEntraIDUserInfoURL,
	}, oidcScopes)
	cfg.GetUserInfo = func(ctx context.Context, tokens socialproviders.OAuth2Tokens) (map[string]any, error) {
		// Step 1: the Graph OIDC profile
		profile := fetchJSON(ctx, o.client(), MicrosoftEntraIDUserInfoURL, tokens.AccessToken)
		if profile == nil {
			return nil, nil
		}
		// Step 2: name falls back to given + family name, email to preferred_username
		name := profile["name"]
		if name == nil {
			if n := strings.TrimSpace(StringOf(profile["given_name"]) + " " + StringOf(profile["family_name"])); n != "" {
				name = n
			}
		}
		return map[string]any{
			"id":            profile["sub"],
			"name":          name,
			"email":         firstNonNil(profile["email"], profile["preferred_username"]),
			"image":         profile["picture"],
			"emailVerified": firstNonNil(profile["email_verified"], false),
		}, nil
	}
	return cfg
}

// ─── Slack ───────────────────────────────────────────────────────────────────

// SlackUserInfoURL is Slack's OpenID Connect userinfo endpoint.
const SlackUserInfoURL = "https://slack.com/api/openid.connect.userInfo"

// Slack is better-auth's slack() helper (Sign in with Slack, OpenID Connect).
func Slack(o PresetOptions) config.ProviderConfig {
	cfg := o.apply(config.ProviderConfig{
		ProviderID:       "slack",
		AuthorizationURL: "https://slack.com/openid/connect/authorize",
		TokenURL:         "https://slack.com/api/openid.connect.token",
		UserInfoURL:      SlackUserInfoURL,
	}, oidcScopes)
	cfg.GetUserInfo = func(ctx context.Context, tokens socialproviders.OAuth2Tokens) (map[string]any, error) {
		profile := fetchJSON(ctx, o.client(), SlackUserInfoURL, tokens.AccessToken)
		if profile == nil {
			return nil, nil
		}
		return map[string]any{
			"id":            firstNonNil(profile["https://slack.com/user_id"], profile["sub"]),
			"name":          profile["name"],
			"email":         profile["email"],
			"image":         firstNonNil(profile["picture"], profile["https://slack.com/user_image_512"]),
			"emailVerified": firstNonNil(profile["email_verified"], false),
		}, nil
	}
	return cfg
}

// ─── LINE ────────────────────────────────────────────────────────────────────

// LineOptions configures LINE (one channel per country: call Line once per channel with its own ProviderID).
type LineOptions struct {
	PresetOptions
	// ProviderID defaults to "line" (e.g. "line-jp", "line-th").
	ProviderID string
}

// LineUserInfoURL is LINE's OIDC userinfo endpoint.
const LineUserInfoURL = "https://api.line.me/oauth2/v2.1/userinfo"

// Line is better-auth's line() helper.
func Line(o LineOptions) config.ProviderConfig {
	id := o.ProviderID
	if id == "" {
		id = "line"
	}
	cfg := o.apply(config.ProviderConfig{
		ProviderID:       id,
		AuthorizationURL: "https://access.line.me/oauth2/v2.1/authorize",
		TokenURL:         "https://api.line.me/oauth2/v2.1/token",
		UserInfoURL:      LineUserInfoURL,
	}, oidcScopes)
	cfg.GetUserInfo = func(ctx context.Context, tokens socialproviders.OAuth2Tokens) (map[string]any, error) {
		// Step 1: the id_token claims, else the userinfo endpoint
		var profile map[string]any
		if tokens.IDToken != "" {
			profile, _ = socialproviders.DecodeJWT(tokens.IDToken)
		}
		if profile == nil {
			profile = fetchJSON(ctx, o.client(), LineUserInfoURL, tokens.AccessToken)
		}
		if profile == nil {
			return nil, nil
		}
		// Step 2: LINE never reports a verified email
		return map[string]any{
			"id": profile["sub"], "name": profile["name"], "email": profile["email"],
			"image": profile["picture"], "emailVerified": false,
		}, nil
	}
	return cfg
}

// ─── HubSpot ─────────────────────────────────────────────────────────────────

// HubSpot is better-auth's hubspot() helper (token endpoint authentication "post", default scope "oauth").
func HubSpot(o PresetOptions) config.ProviderConfig {
	cfg := o.apply(config.ProviderConfig{
		ProviderID:       "hubspot",
		AuthorizationURL: "https://app.hubspot.com/oauth/authorize",
		TokenURL:         "https://api.hubapi.com/oauth/v1/token",
		Authentication:   socialproviders.AuthPost,
	}, []string{"oauth"})
	cfg.GetUserInfo = func(ctx context.Context, tokens socialproviders.OAuth2Tokens) (map[string]any, error) {
		// Step 1: HubSpot's token introspection endpoint describes the user
		profile := fetchJSON(ctx, o.client(), "https://api.hubapi.com/oauth/v1/access-tokens/"+url.PathEscape(tokens.AccessToken), "")
		if profile == nil {
			return nil, nil
		}
		// Step 2: user_id, else signed_access_token.userId
		id := profile["user_id"]
		if id == nil {
			if sat, ok := profile["signed_access_token"].(map[string]any); ok {
				id = sat["userId"]
			}
		}
		if StringOf(id) == "" {
			return nil, nil
		}
		return map[string]any{"id": id, "name": profile["user"], "email": profile["user"], "emailVerified": false}, nil
	}
	return cfg
}

// ─── Patreon ─────────────────────────────────────────────────────────────────

// Patreon is better-auth's patreon() helper.
func Patreon(o PresetOptions) config.ProviderConfig {
	cfg := o.apply(config.ProviderConfig{
		ProviderID:       "patreon",
		AuthorizationURL: "https://www.patreon.com/oauth2/authorize",
		TokenURL:         "https://www.patreon.com/api/oauth2/token",
	}, []string{"identity[email]"})
	cfg.GetUserInfo = func(ctx context.Context, tokens socialproviders.OAuth2Tokens) (map[string]any, error) {
		profile := fetchJSON(ctx, o.client(), "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified", tokens.AccessToken)
		data, _ := profile["data"].(map[string]any)
		if data == nil {
			return nil, nil
		}
		attrs, _ := data["attributes"].(map[string]any)
		if attrs == nil {
			attrs = map[string]any{}
		}
		return map[string]any{
			"id": data["id"], "name": attrs["full_name"], "email": attrs["email"],
			"image": attrs["image_url"], "emailVerified": attrs["is_email_verified"],
		}, nil
	}
	return cfg
}

// ─── Gumroad ─────────────────────────────────────────────────────────────────

// Gumroad is better-auth's gumroad() helper.
func Gumroad(o PresetOptions) config.ProviderConfig {
	cfg := o.apply(config.ProviderConfig{
		ProviderID:       "gumroad",
		AuthorizationURL: "https://gumroad.com/oauth/authorize",
		TokenURL:         "https://api.gumroad.com/oauth/token",
	}, []string{"view_profile"})
	cfg.GetUserInfo = func(ctx context.Context, tokens socialproviders.OAuth2Tokens) (map[string]any, error) {
		profile := fetchJSON(ctx, o.client(), "https://api.gumroad.com/v2/user", tokens.AccessToken)
		user, _ := profile["user"].(map[string]any)
		if profile == nil || !BoolOf(profile["success"]) || user == nil {
			return nil, nil
		}
		return map[string]any{
			"id": user["user_id"], "name": user["name"], "email": user["email"],
			"image": user["profile_url"], "emailVerified": false,
		}, nil
	}
	return cfg
}
