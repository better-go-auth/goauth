// Package siwe ports better-auth's siwe plugin: Sign-In with Ethereum (EIP-4361).
//
// The client asks for a nonce for its wallet address and chain (POST /siwe/nonce), builds an EIP-4361
// message with it, has the wallet sign it (personal_sign, EIP-191) and posts message and signature to
// POST /siwe/verify. goauth checks the nonce, the message's domain / address / chain / validity window and
// the signature (by default with secp256k1 public-key recovery, see package eip4361), then signs the
// wallet's user in, creating the user on first sign-in.
//
// The plugin declares better-auth's walletAddress table with plugins.SchemaProvider; goauth's migrator
// creates it and the plugin uses it through InitContext.Adapter.
package siwe

import (
	"errors"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	humasiwe "github.com/better-go-auth/goauth/src/plugins/siwe/adapters/huma"
	siweconfig "github.com/better-go-auth/goauth/src/plugins/siwe/config"
	"github.com/better-go-auth/goauth/src/plugins/siwe/services"
	"github.com/better-go-auth/goauth/src/schema"
)

// PluginID is better-auth's plugin id.
const PluginID = "siwe"

// Plugin implements plugins.Plugin and plugins.SchemaProvider for better-auth's siwe plugin.
type Plugin struct {
	config  siweconfig.SIWEConfig
	kit     *pluginkit.Kit
	service *services.Service
	handler *humasiwe.Handler
}

var (
	_ plugins.Plugin         = (*Plugin)(nil)
	_ plugins.SchemaProvider = (*Plugin)(nil)
)

// Option configures the plugin.
type Option func(*Plugin)

// WithDomain sets the domain SIWE messages must be issued for.
func WithDomain(domain string) Option { return func(p *Plugin) { p.config.Domain = domain } }

// WithAnonymous allows (true, the default) or forbids sign-ins without an email.
func WithAnonymous(anonymous bool) Option {
	return func(p *Plugin) { p.config.Anonymous = &anonymous }
}

// WithGetNonce sets the nonce generator.
func WithGetNonce(fn siweconfig.GetNonceFunc) Option {
	return func(p *Plugin) { p.config.GetNonce = fn }
}

// WithVerifyMessage replaces the default EIP-191 signature verifier.
func WithVerifyMessage(fn siweconfig.VerifyMessageFunc) Option {
	return func(p *Plugin) { p.config.VerifyMessage = fn }
}

// WithENSLookup sets the ENS name / avatar lookup for new users.
func WithENSLookup(fn siweconfig.ENSLookupFunc) Option {
	return func(p *Plugin) { p.config.ENSLookup = fn }
}

// WithEmailDomainName sets the domain of new users' placeholder emails.
func WithEmailDomainName(domain string) Option {
	return func(p *Plugin) { p.config.EmailDomainName = domain }
}

// New creates the plugin.
func New(cfg siweconfig.SIWEConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ID returns "siwe".
func (p *Plugin) ID() string { return PluginID }

// Schema declares better-auth's walletAddress table (renamed with ModelName / FieldNames).
func (p *Plugin) Schema() schema.PluginSchema {
	fields := map[string]schema.Field{
		services.FieldUserID: {
			Type: schema.String, Required: true, Index: true,
			References: &schema.Reference{Model: schema.ModelUser, Field: "id"},
		},
		services.FieldAddress:   {Type: schema.String, Required: true},
		services.FieldChainID:   {Type: schema.Number, Required: true},
		services.FieldIsPrimary: {Type: schema.Boolean, Default: false},
		services.FieldCreatedAt: {Type: schema.Date, Required: true},
	}
	for name, column := range p.config.FieldNames {
		if f, ok := fields[name]; ok {
			f.FieldName = column
			fields[name] = f
		}
	}
	return schema.PluginSchema{services.Model: {ModelName: p.config.ModelName, Fields: fields}}
}

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("siwe: init context is required")
	}
	// Step 1: the walletAddress table is accessed through the adapter
	if ictx.Adapter == nil {
		return errors.New("siwe: needs InitContext.Adapter (GoAuthOptions.Conn or adapter-based repositories)")
	}
	// Step 2: without a Domain the base URL's host is used, so one of them must be set
	if p.config.Domain == "" && ictx.Config.BaseURL == "" && ictx.Config.DynamicBaseURL == nil {
		return errors.New("siwe: Domain is required when no BaseURL is configured")
	}
	// Step 3: shared plugin runtime (sessions, cookies, origin check)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit
	// Step 4: service and routes
	p.service = services.New(p.config, kit, ictx.Adapter)
	p.handler = humasiwe.NewHandler(p.service)
	humasiwe.RegisterRoutes(ictx.Api, kit, p.handler)
	return nil
}

// Migrator returns nil: the walletAddress table comes from the plugin schema (Schema).
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any { return map[string]any{"siwe": p.service} }

// Routes returns nil: routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the configuration.
func (p *Plugin) Config() siweconfig.SIWEConfig { return p.config }
