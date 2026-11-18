// Package sso is goauth's port of better-auth's sso plugin (@better-auth/sso 1.6.16): enterprise single sign-on
// with OIDC and SAML 2.0 identity providers registered per user or per organization.
//
//	sso.New(ssoconfig.SSOConfig{
//		OrganizationProvisioning: &ssoconfig.OrganizationProvisioning{DefaultRole: "member"},
//	})
//
// Endpoints: POST /sso/register, POST /sign-in/sso, GET /sso/callback/{providerId} (and /sso/callback with
// RedirectURI), GET|POST /sso/saml2/callback/{providerId}, POST /sso/saml2/sp/acs/{providerId},
// GET /sso/saml2/sp/metadata, GET|POST /sso/saml2/sp/slo/{providerId}, POST /sso/saml2/logout/{providerId},
// GET /sso/providers, GET /sso/get-provider, POST /sso/update-provider, POST /sso/delete-provider and, with
// DomainVerification.Enabled, POST /sso/request-domain-verification and POST /sso/verify-domain.
//
// Providers live in the ssoProvider table, declared with plugins.SchemaProvider (created by goauth's
// migrator). SAML messages are validated with github.com/crewjam/saml. Organization features need the
// organization plugin (plugins.OrganizationStoreProvider).
package sso

import (
	"errors"
	"fmt"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/plugins/social"
	humasso "github.com/better-go-auth/goauth/src/plugins/sso/adapters/huma"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
	"github.com/better-go-auth/goauth/src/plugins/sso/services"
	"github.com/better-go-auth/goauth/src/schema"
)

// PluginID is better-auth's plugin id.
const PluginID = "sso"

// Plugin implements plugins.Plugin, plugins.SchemaProvider and plugins.EndpointHooksProvider for better-auth's
// sso plugin.
type Plugin struct {
	config  ssoconfig.SSOConfig
	service *services.Service
}

var (
	_ plugins.Plugin                = (*Plugin)(nil)
	_ plugins.SchemaProvider        = (*Plugin)(nil)
	_ plugins.EndpointHooksProvider = (*Plugin)(nil)
)

// New creates the sso plugin.
func New(cfg ssoconfig.SSOConfig) *Plugin {
	return &Plugin{config: cfg.WithDefaults()}
}

// ID returns "sso".
func (p *Plugin) ID() string { return PluginID }

// Schema declares the ssoProvider table (better-auth's plugin schema; domainVerified only with domain
// verification, column names from Fields).
func (p *Plugin) Schema() schema.PluginSchema {
	f := p.config.Fields
	fields := map[string]schema.Field{
		"issuer":         {Type: schema.String, Required: true, FieldName: f.Issuer},
		"oidcConfig":     {Type: schema.String, Required: false, FieldName: f.OIDCConfig},
		"samlConfig":     {Type: schema.String, Required: false, FieldName: f.SAMLConfig},
		"userId":         {Type: schema.String, Required: true, References: &schema.Reference{Model: schema.ModelUser, Field: "id"}, FieldName: f.UserID},
		"providerId":     {Type: schema.String, Required: true, Unique: true, FieldName: f.ProviderID},
		"organizationId": {Type: schema.String, Required: false, FieldName: f.OrganizationID},
		"domain":         {Type: schema.String, Required: true, FieldName: f.Domain},
	}
	if p.config.DomainVerification.Enabled {
		fields["domainVerified"] = schema.Field{Type: schema.Boolean, Required: false}
	}
	model := schema.Model{Fields: fields}
	if p.config.ModelName != ssoconfig.DefaultModelName {
		model.ModelName = p.config.ModelName
	}
	return schema.PluginSchema{services.Model: model}
}

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	// Step 1: shared plugin runtime and the provider table's adapter
	if ictx == nil {
		return errors.New("sso plugin: init context is required")
	}
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return fmt.Errorf("sso plugin: %w", err)
	}
	// Step 2: the service, sharing core's account options (linking, token storage, state strategy)
	svc, err := services.New(p.config, services.Deps{
		Kit:     kit,
		Adapter: ictx.Adapter,
		OAuth:   social.FromAuthConfig(ictx.Config).Config(),
		Plugins: ictx.Plugins,
	})
	if err != nil {
		return fmt.Errorf("sso plugin: %w", err)
	}
	p.service = svc
	// Step 3: routes
	humasso.Register(kit, ictx.Api, humasso.NewHandler(svc), p.config.DomainVerification.Enabled)
	return nil
}

// EndpointHooks returns better-auth's sso hooks: before /sign-out the SAML session records are dropped
// (Single Logout), after an OAuth callback (/callback/{id}) the new user joins the organization owning their
// email domain.
func (p *Plugin) EndpointHooks() endpointhooks.Hooks {
	if p.service == nil {
		return endpointhooks.Hooks{}
	}
	svc := p.service
	return endpointhooks.Hooks{
		Before: []endpointhooks.BeforeHook{{
			Matcher: endpointhooks.MatchPaths("/sign-out"),
			Handler: func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
				if !p.config.SAML.EnableSingleLogout {
					return nil, nil
				}
				if sw := svc.Kit().CurrentOrResolve(c.Ctx); sw != nil {
					svc.ClearSAMLSession(c.Ctx, sw.Session.ID)
				}
				return nil, nil
			},
		}},
		After: []endpointhooks.AfterHook{{
			Matcher: endpointhooks.MatchPrefix("/callback/"),
			Handler: func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
				sw := c.NewSession()
				if sw == nil {
					return nil, nil
				}
				user, err := svc.Kit().Repos.FindUserByID(c.Ctx, sw.User.ID)
				if err != nil || user == nil {
					return nil, nil
				}
				return nil, svc.AssignOrganizationByDomain(c.Ctx, user)
			},
		}},
	}
}

// Migrator returns nil: the ssoProvider table comes from the plugin schema (Schema).
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the service.
func (p *Plugin) Services() map[string]any { return map[string]any{"sso": p.service} }

// Routes returns nil: the endpoints are mounted on the Huma API in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() ssoconfig.SSOConfig { return p.config }
