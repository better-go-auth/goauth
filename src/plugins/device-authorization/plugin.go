// Package deviceauthorization ports better-auth's device-authorization plugin: the OAuth 2.0 Device
// Authorization Grant (RFC 8628) for devices without a browser or keyboard (CLIs, TVs).
//
// The device asks for a code (POST /device/code), shows the user code and verification URI, and polls
// POST /device/token. The user opens the verification page signed in, which claims the code (GET /device),
// and approves (POST /device/approve) or denies (POST /device/deny) it. The next poll returns the new
// session's token as access_token.
//
// The plugin declares better-auth's deviceCode table with plugins.SchemaProvider; goauth's migrator creates
// it and the plugin uses it through InitContext.Adapter.
package deviceauthorization

import (
	"errors"

	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humadevice "github.com/better-go-auth/goauth/src/plugins/device-authorization/adapters/huma"
	daconfig "github.com/better-go-auth/goauth/src/plugins/device-authorization/config"
	"github.com/better-go-auth/goauth/src/plugins/device-authorization/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/schema"
)

// PluginID is better-auth's plugin id.
const PluginID = "device-authorization"

// ErrorCodes are better-auth's DEVICE_AUTHORIZATION_ERROR_CODES.
var ErrorCodes = services.ErrorCodes

// Plugin implements plugins.Plugin and plugins.SchemaProvider for better-auth's device-authorization plugin.
type Plugin struct {
	config  daconfig.DeviceAuthorizationConfig
	kit     *pluginkit.Kit
	service *services.Service
	handler *humadevice.Handler
}

var (
	_ plugins.Plugin         = (*Plugin)(nil)
	_ plugins.SchemaProvider = (*Plugin)(nil)
)

// Option configures the plugin.
type Option func(*Plugin)

// WithValidateClient sets the client_id check.
func WithValidateClient(fn daconfig.ValidateClientFunc) Option {
	return func(p *Plugin) { p.config.ValidateClient = fn }
}

// WithOnDeviceAuthRequest sets the hook called for every device authorization request.
func WithOnDeviceAuthRequest(fn daconfig.DeviceAuthRequestFunc) Option {
	return func(p *Plugin) { p.config.OnDeviceAuthRequest = fn }
}

// WithVerificationURI sets the verification page (absolute URL or path).
func WithVerificationURI(uri string) Option {
	return func(p *Plugin) { p.config.VerificationURI = uri }
}

// New creates the plugin.
func New(cfg daconfig.DeviceAuthorizationConfig, opts ...Option) *Plugin {
	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	p.config = p.config.WithDefaults()
	return p
}

// ID returns "device-authorization".
func (p *Plugin) ID() string { return PluginID }

// Schema declares better-auth's deviceCode table (renamed with ModelName / FieldNames).
func (p *Plugin) Schema() schema.PluginSchema {
	fields := map[string]schema.Field{
		services.FieldDeviceCode:      {Type: schema.String, Required: true},
		services.FieldUserCode:        {Type: schema.String, Required: true},
		services.FieldUserID:          {Type: schema.String},
		services.FieldExpiresAt:       {Type: schema.Date, Required: true},
		services.FieldStatus:          {Type: schema.String, Required: true},
		services.FieldLastPolledAt:    {Type: schema.Date},
		services.FieldPollingInterval: {Type: schema.Number},
		services.FieldClientID:        {Type: schema.String},
		services.FieldScope:           {Type: schema.String},
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
		return errors.New("device-authorization: init context is required")
	}
	// Step 1: the deviceCode table is accessed through the adapter
	if ictx.Adapter == nil {
		return errors.New("device-authorization: needs InitContext.Adapter (GoAuthOptions.Conn or adapter-based repositories)")
	}
	// Step 2: shared plugin runtime (sessions, cookies, origin check)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit
	// Step 3: service and routes
	p.service = services.New(p.config, kit, ictx.Adapter)
	p.handler = humadevice.NewHandler(p.service)
	humadevice.RegisterRoutes(ictx.Api, kit, p.handler)
	return nil
}

// Migrator returns nil: the deviceCode table comes from the plugin schema (Schema).
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the plugin service.
func (p *Plugin) Services() map[string]any { return map[string]any{"deviceAuthorization": p.service} }

// Routes returns nil: routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the plugin service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Config returns the effective configuration.
func (p *Plugin) Config() daconfig.DeviceAuthorizationConfig { return p.config }
