// Package services implements better-auth's sso plugin (@better-auth/sso 1.6.16): SSO provider management,
// OIDC sign-in (discovery, authorization code + PKCE, id_token / userinfo), SAML 2.0 sign-in (SP-initiated
// and IdP-initiated, InResponseTo tracking, replay protection, Single Logout), domain verification and
// organization provisioning.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	socialsvc "github.com/better-go-auth/goauth/src/plugins/social/services"
	"github.com/better-go-auth/goauth/src/plugins/sso/config"
)

// Model is the logical model name of the provider table (better-auth's schema key).
const Model = "ssoProvider"

// Deps are the runtime dependencies of the service.
type Deps struct {
	// Kit is the shared plugin runtime.
	Kit *pluginkit.Kit
	// Adapter reads and writes the ssoProvider table.
	Adapter adapter.Adapter
	// OAuth is the shared OAuth machinery (state, account linking, session cookies).
	OAuth socialconfig.SocialConfig
	// Plugins are the installed plugins (organization plugin lookup, reserved provider ids).
	Plugins []plugins.Plugin
}

// Service runs the sso flows.
type Service struct {
	kit     *pluginkit.Kit
	cfg     config.SSOConfig
	store   adapter.Adapter
	oauth   *socialsvc.Service
	plugins []plugins.Plugin
}

// New builds the service.
func New(cfg config.SSOConfig, deps Deps) (*Service, error) {
	// Step 1: the dependencies every endpoint uses
	if deps.Kit == nil {
		return nil, errors.New("sso: plugin kit is required")
	}
	if deps.Adapter == nil {
		return nil, errors.New("sso: the storage adapter is required (configure GoAuthOptions.Conn or adapter-based repositories)")
	}
	// Step 2: the OAuth machinery of the social plugin (without providers of its own)
	oauthCfg := deps.OAuth
	oauthCfg.Providers = nil
	oauth, err := socialsvc.New(deps.Kit, oauthCfg)
	if err != nil {
		return nil, err
	}
	return &Service{kit: deps.Kit, cfg: cfg.WithDefaults(), store: deps.Adapter, oauth: oauth, plugins: deps.Plugins}, nil
}

// Kit exposes the plugin kit.
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// Config returns the effective configuration.
func (s *Service) Config() config.SSOConfig { return s.cfg }

// orgs returns the organization plugin's store, or nil (better-auth's hasPlugin("organization")).
func (s *Service) orgs() plugins.OrganizationStore { return plugins.FindOrganizationStore(s.plugins) }

// isTrustedOrigin is better-auth's ctx.context.isTrustedOrigin(url) (relative paths refused).
func (s *Service) isTrustedOrigin(ctx context.Context) func(string) bool {
	return func(u string) bool { return s.kit.Origins.IsTrustedFor(s.kit.Request(ctx), u, false) }
}

// ─── provider rows ───────────────────────────────────────────────────────────

// providerFromRecord parses a stored row (configs that fail to parse are dropped, like safeJsonParse || undefined).
func providerFromRecord(r adapter.Record) *config.Provider {
	p := &config.Provider{
		ID:             str(r["id"]),
		Issuer:         str(r["issuer"]),
		Domain:         str(r["domain"]),
		ProviderID:     str(r["providerId"]),
		UserID:         str(r["userId"]),
		OrganizationID: str(r["organizationId"]),
	}
	if v, ok := r["domainVerified"]; ok {
		b, _ := v.(bool)
		p.DomainVerified = &b
	}
	if raw := str(r["oidcConfig"]); raw != "" {
		var c config.OIDCConfig
		if json.Unmarshal([]byte(raw), &c) == nil {
			p.OIDCConfig = &c
		}
	}
	if raw := str(r["samlConfig"]); raw != "" {
		var c config.SAMLConfig
		if json.Unmarshal([]byte(raw), &c) == nil {
			p.SAMLConfig = &c
		}
	}
	return p
}

// findProviderRecord returns the stored row with providerId, or nil.
func (s *Service) findProviderRecord(ctx context.Context, providerID string) (adapter.Record, error) {
	r, err := s.store.FindOne(ctx, Model, []adapter.Where{{Field: "providerId", Value: providerID}})
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, nil
	}
	return r, err
}

// findStoredProvider returns the stored provider with providerId, or nil.
func (s *Service) findStoredProvider(ctx context.Context, providerID string) (*config.Provider, adapter.Record, error) {
	r, err := s.findProviderRecord(ctx, providerID)
	if err != nil || r == nil {
		return nil, nil, err
	}
	return providerFromRecord(r), r, nil
}

// defaultProvider returns the defaultSSO entry with providerId as a provider (userId "default", verified when
// domain verification is on), or nil. issuer picks the issuer of the given config kind.
func (s *Service) defaultProvider(match func(config.DefaultProvider) bool, issuerFrom string) *config.Provider {
	for _, d := range s.cfg.DefaultSSO {
		if !match(d) {
			continue
		}
		p := &config.Provider{ProviderID: d.ProviderID, Domain: d.Domain, UserID: "default", OIDCConfig: d.OIDCConfig, SAMLConfig: d.SAMLConfig}
		switch issuerFrom {
		case "saml":
			if d.SAMLConfig != nil {
				p.Issuer = d.SAMLConfig.Issuer
			}
		case "oidc":
			if d.OIDCConfig != nil {
				p.Issuer = d.OIDCConfig.Issuer
			}
		default:
			if d.SAMLConfig != nil && d.SAMLConfig.Issuer != "" {
				p.Issuer = d.SAMLConfig.Issuer
			} else if d.OIDCConfig != nil {
				p.Issuer = d.OIDCConfig.Issuer
			}
		}
		if s.cfg.DomainVerification.Enabled {
			p.DomainVerified = config.Bool(true)
		}
		return p
	}
	return nil
}

// findSAMLProvider is better-auth's findSAMLProvider: defaultSSO first, then the database.
func (s *Service) findSAMLProvider(ctx context.Context, providerID string) (*config.Provider, error) {
	if p := s.defaultProvider(func(d config.DefaultProvider) bool { return d.ProviderID == providerID }, "saml"); p != nil {
		return p, nil
	}
	p, _, err := s.findStoredProvider(ctx, providerID)
	return p, err
}

// listProviderRecords returns every stored provider.
func (s *Service) listProviderRecords(ctx context.Context, where []adapter.Where) ([]adapter.Record, error) {
	return s.store.FindMany(ctx, Model, adapter.Query{Where: where})
}

// ─── domains ─────────────────────────────────────────────────────────────────

// domainMatches reports whether search equals or is a subdomain of a domain in the comma-separated list.
func domainMatches(search, list string) bool {
	search = strings.ToLower(search)
	for _, d := range strings.Split(list, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if search == d || strings.HasSuffix(search, "."+d) {
			return true
		}
	}
	return false
}

// validateEmailDomain is better-auth's validateEmailDomain.
func validateEmailDomain(email, domain string) bool {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) < 2 || parts[1] == "" || domain == "" {
		return false
	}
	return domainMatches(strings.ToLower(parts[1]), domain)
}

// maskClientID is better-auth's maskClientId.
func maskClientID(id string) string {
	if len(id) <= 4 {
		return "****"
	}
	return "****" + id[len(id)-4:]
}

// redirectURI is better-auth's getOIDCRedirectURI: the shared redirectURI option, else /sso/callback/<id>.
func (s *Service) redirectURI(ctx context.Context, providerID string) string {
	base := s.kit.RequestBaseURL(ctx)
	if r := strings.TrimSpace(s.cfg.RedirectURI); r != "" {
		if isAbsoluteURL(s.cfg.RedirectURI) {
			return s.cfg.RedirectURI
		}
		if strings.HasPrefix(s.cfg.RedirectURI, "/") {
			return base + s.cfg.RedirectURI
		}
		return base + "/" + s.cfg.RedirectURI
	}
	return base + "/sso/callback/" + providerID
}

// isAbsoluteURL reports whether raw parses as an absolute URL (JavaScript's new URL(raw) succeeding).
func isAbsoluteURL(raw string) bool {
	_, err := parseEndpointURL("url", raw, "")
	if err == nil {
		return true
	}
	// non-http schemes are still absolute for new URL()
	i := strings.Index(raw, ":")
	return i > 0 && !strings.ContainsAny(raw[:i], "/?#")
}

// whereEq is a single equality condition.
func whereEq(field string, value any) []adapter.Where {
	return []adapter.Where{{Field: field, Value: value}}
}

// ignoreNotFound turns adapter.ErrNotFound into nil and wraps other errors.
func ignoreNotFound(err error) error {
	if err == nil || errors.Is(err, adapter.ErrNotFound) {
		return nil
	}
	return errorf("find provider: %w", err)
}

// errorf wraps an unexpected storage error.
func errorf(format string, args ...any) error { return fmt.Errorf("sso: "+format, args...) }
