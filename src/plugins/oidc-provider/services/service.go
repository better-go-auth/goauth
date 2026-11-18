// Package services implements better-auth's oidc-provider plugin: the authorization code flow with PKCE,
// consent, the token, userinfo, dynamic client registration and RP-initiated logout endpoints, the
// discovery document, and the after hook that resumes an authorization request once the user signed in.
//
// Every endpoint returns an *endpointhooks.Response with the exact status, headers and JSON body of
// better-auth (RFC 6749 {"error", "error_description"} bodies included); goauth-style {"code", "message"}
// errors (validation, missing session) are returned as errors.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/models"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	jwtservices "github.com/better-go-auth/goauth/src/plugins/jwt/services"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// JWTSigner is what the oidc-provider needs from the jwt plugin (*jwt.Plugin implements it).
type JWTSigner interface {
	SignJWT(ctx context.Context, payload map[string]any, opts *jwtservices.SignJWTOptions) (string, error)
	VerifyJWT(ctx context.Context, token, issuer string) (map[string]any, error)
	Config() jwtconfig.JWTConfig
}

// Deps are the runtime dependencies of the service.
type Deps struct {
	// Kit gives the repositories, sessions, cookies and base URL.
	Kit *pluginkit.Kit
	// Store reads and writes the plugin tables (InitContext.Adapter).
	Store adapter.Adapter
	// JWT returns the installed jwt plugin, or nil (better-auth's ctx.context.getPlugin("jwt")).
	JWT func() JWTSigner
}

// Service implements the oidc-provider endpoints.
type Service struct {
	cfg  oidcconfig.Config
	deps Deps
}

// New builds the service; cfg gets better-auth's defaults.
func New(cfg oidcconfig.Config, deps Deps) *Service {
	return &Service{cfg: cfg.WithDefaults(), deps: deps}
}

// Config returns the effective configuration.
func (s *Service) Config() oidcconfig.Config { return s.cfg }

// Kit returns the plugin kit.
func (s *Service) Kit() *pluginkit.Kit { return s.deps.Kit }

// Store returns the adapter holding the plugin tables.
func (s *Service) Store() adapter.Adapter { return s.deps.Store }

// jwt returns the jwt plugin or nil.
func (s *Service) jwt() JWTSigner {
	if s.deps.JWT == nil {
		return nil
	}
	return s.deps.JWT()
}

// ─── clients ─────────────────────────────────────────────────────────────────

// GetClient is better-auth's getClient: a trusted client with that ID, else the oauthApplication row
// (nil when neither exists).
func (s *Service) GetClient(ctx context.Context, clientID string) (*oidcconfig.Client, error) {
	// Step 1: configured trusted clients win
	for i := range s.cfg.TrustedClients {
		if s.cfg.TrustedClients[i].ClientID == clientID {
			c := s.cfg.TrustedClients[i]
			return &c, nil
		}
	}
	// Step 2: the database
	return s.GetStoredClient(ctx, clientID)
}

// GetStoredClient returns the oauthApplication row with clientID as a Client (nil when missing).
func (s *Service) GetStoredClient(ctx context.Context, clientID string) (*oidcconfig.Client, error) {
	if s.deps.Store == nil {
		return nil, errors.New("oidc-provider: no adapter")
	}
	rec, err := s.findOne(ctx, oidcconfig.ModelOAuthApplication, []adapter.Where{{Field: "clientId", Value: clientID}})
	if err != nil || rec == nil {
		return nil, err
	}
	return ClientFromRecord(rec), nil
}

// ClientFromRecord converts an oauthApplication record (redirectUrls split at commas, metadata parsed).
func ClientFromRecord(rec adapter.Record) *oidcconfig.Client {
	c := &oidcconfig.Client{
		ClientID:     str(rec["clientId"]),
		ClientSecret: str(rec["clientSecret"]),
		Type:         str(rec["type"]),
		Name:         str(rec["name"]),
		Icon:         str(rec["icon"]),
		Metadata:     map[string]any{},
		RedirectURLs: strings.Split(str(rec["redirectUrls"]), ","),
	}
	if b, ok := rec["disabled"].(bool); ok {
		c.Disabled = b
	}
	if m := str(rec["metadata"]); m != "" {
		var md map[string]any
		if json.Unmarshal([]byte(m), &md) == nil && md != nil {
			c.Metadata = md
		}
	}
	return c
}

// str reads a record value as a string ("" for nil and other types).
func str(v any) string {
	s, _ := v.(string)
	return s
}

// timeOf reads a record date.
func timeOf(v any) time.Time {
	t, _ := v.(time.Time)
	return t
}

// ─── client secrets ──────────────────────────────────────────────────────────

// StoreClientSecret is better-auth's storeClientSecret: the value written to oauthApplication.clientSecret.
func (s *Service) StoreClientSecret(ctx context.Context, secret string) (string, error) {
	st := s.cfg.StoreClientSecret
	switch {
	case st.Hash != nil:
		return st.Hash(ctx, secret)
	case st.Encrypt != nil:
		return st.Encrypt(ctx, secret)
	case st.Mode == oidcconfig.SecretEncrypted:
		return s.keys().Encrypt(secret)
	case st.Mode == oidcconfig.SecretHashed:
		return S256(secret), nil
	}
	return secret, nil
}

// VerifyStoredClientSecret is better-auth's verifyStoredClientSecret (constant-time comparisons).
func (s *Service) VerifyStoredClientSecret(ctx context.Context, stored, secret string) bool {
	st := s.cfg.StoreClientSecret
	switch {
	case st.Mode == oidcconfig.SecretEncrypted && st.Hash == nil && st.Encrypt == nil:
		plain, err := s.keys().Decrypt(stored)
		return err == nil && authcrypto.SecureEqual(plain, secret)
	case st.Mode == oidcconfig.SecretHashed && st.Hash == nil && st.Encrypt == nil:
		return authcrypto.SecureEqual(S256(secret), stored)
	case st.Hash != nil:
		h, err := st.Hash(ctx, secret)
		return err == nil && authcrypto.SecureEqual(h, stored)
	case st.Decrypt != nil:
		plain, err := st.Decrypt(ctx, stored)
		return err == nil && authcrypto.SecureEqual(plain, secret)
	}
	return authcrypto.SecureEqual(secret, stored)
}

// keys returns the auth secret configuration (better-auth's ctx.context.secretConfig).
func (s *Service) keys() authcrypto.SecretKeys {
	return s.deps.Kit.Cookies.Keys()
}

// ─── metadata ────────────────────────────────────────────────────────────────

// Issuer is the discovery issuer: the jwt plugin's issuer when the jwt plugin is installed, else the
// configured BaseURL (better-auth's options.baseURL; with a dynamic base URL, the request's origin).
func (s *Service) Issuer(ctx context.Context) string {
	if j := s.jwt(); j != nil && j.Config().JWT.Issuer != "" {
		return j.Config().JWT.Issuer
	}
	return s.OptionsBaseURL(ctx)
}

// OptionsBaseURL is better-auth's ctx.context.options.baseURL: the configured origin (or, with a
// dynamic base URL, the one resolved for the request).
func (s *Service) OptionsBaseURL(ctx context.Context) string {
	if b := strings.TrimRight(s.deps.Kit.Conf.BaseURL, "/"); b != "" {
		return b
	}
	return s.deps.Kit.Conf.RequestBaseURL(ctx)
}

// Metadata is the /.well-known/openid-configuration document (better-auth's getMetadata) with
// Config.Metadata applied on top.
func (s *Service) Metadata(ctx context.Context) map[string]any {
	// Step 1: endpoint URLs under the auth base URL
	base := s.deps.Kit.BaseURL(ctx)
	algs := []string{"HS256"}
	if s.cfg.UseJWTPlugin {
		algs = []string{"RS256", "EdDSA"}
	}
	md := map[string]any{
		"issuer":                                s.Issuer(ctx),
		"authorization_endpoint":                base + "/oauth2/authorize",
		"token_endpoint":                        base + "/oauth2/token",
		"userinfo_endpoint":                     base + "/oauth2/userinfo",
		"jwks_uri":                              base + "/jwks",
		"registration_endpoint":                 base + "/oauth2/register",
		"end_session_endpoint":                  base + "/oauth2/endsession",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"acr_values_supported":                  []string{"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": algs,
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "nbf", "iat", "jti", "email", "email_verified", "name"},
	}
	// Step 2: the configured overrides
	for k, v := range s.cfg.Metadata {
		md[k] = v
	}
	return md
}

// UserByID loads a user (nil when missing).
func (s *Service) UserByID(ctx context.Context, id string) *models.User {
	u, err := pluginkit.AcceptNotFound(s.deps.Kit.Repos.FindUserByID(ctx, id))
	if err != nil {
		return nil
	}
	return u
}

// findOne is Store.FindOne with "not found" as (nil, nil), like better-auth's adapter.findOne.
func (s *Service) findOne(ctx context.Context, model string, where []adapter.Where) (adapter.Record, error) {
	rec, err := s.deps.Store.FindOne(ctx, model, where)
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, nil
	}
	return rec, err
}
