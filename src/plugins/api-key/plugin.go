// Package apikey ports @better-auth/api-key 1.6.16 (better-auth's apiKey() plugin): API keys stored in the
// `apikey` table or the secondary storage (SHA-256 hashed), with per-key usage limits (remaining, refills),
// rate limits, expiry, permissions (checked with src/providers/access) and metadata, organization-owned
// keys, several configurations (configId), and sessions mocked from an API key header.
//
// HTTP routes (under BasePath): POST /api-key/create, GET /api-key/get, POST /api-key/update,
// POST /api-key/delete, GET /api-key/list. verifyApiKey and deleteAllExpiredApiKeys are server-only in
// better-auth: here they are Go methods (Plugin.VerifyAPIKey, Plugin.DeleteAllExpiredAPIKeys), next to the
// server versions of the routes (CreateAPIKey, GetAPIKey, UpdateAPIKey, DeleteAPIKey, ListAPIKeys), which
// may set server-only fields. Plugin.Middleware / HTTPMiddleware authenticate your own routes by API key.
//
// The table is declared through plugins.SchemaProvider and created by goauth's migrator.
package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humaapikey "github.com/better-go-auth/goauth/src/plugins/api-key/adapters/huma"
	"github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/plugins/api-key/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/danielgtaylor/huma/v2"
)

// PluginID is better-auth's plugin id.
const PluginID = "api-key"

// Re-exported service types, so callers only import this package.
type (
	// APIKey is a stored key (the hashed value in Key).
	APIKey = services.APIKey
	// APIKeyResponse is a key as the endpoints return it (no key value).
	APIKeyResponse = services.APIKeyResponse
	// CreateAPIKeyResponse is a new key with its plain value.
	CreateAPIKeyResponse = services.CreateAPIKeyResponse
	// CreateAPIKeyInput is the input of CreateAPIKey.
	CreateAPIKeyInput = services.CreateInput
	// UpdateAPIKeyInput is the input of UpdateAPIKey.
	UpdateAPIKeyInput = services.UpdateInput
	// VerifyAPIKeyInput is the input of VerifyAPIKey.
	VerifyAPIKeyInput = services.VerifyInput
	// VerifyAPIKeyResult is better-auth's {valid, error, key}.
	VerifyAPIKeyResult = services.VerifyResult
	// ListAPIKeysResult is better-auth's {apiKeys, total, limit, offset}.
	ListAPIKeysResult = services.ListResult
	// OrganizationAuthorizer answers organization questions for organization-owned keys.
	OrganizationAuthorizer = services.OrganizationAuthorizer
	// Nullable is an optional value that may be an explicit null (UpdateAPIKeyInput).
	Nullable[T any] = services.Nullable[T]
)

// Value returns a Nullable holding v.
func Value[T any](v T) Nullable[T] { return services.Value(v) }

// Null returns a Nullable holding an explicit null.
func Null[T any]() Nullable[T] { return services.Null[T]() }

// ErrorCodes are better-auth's API_KEY_ERROR_CODES.
var ErrorCodes = services.ErrorCodes

// Plugin implements plugins.Plugin, plugins.SchemaProvider and plugins.EndpointHooksProvider.
type Plugin struct {
	configs []config.Configuration
	opts    pluginOptions
	err     error

	kit     *pluginkit.Kit
	service *services.Service
	handler *humaapikey.Handler
}

var (
	_ plugins.Plugin                = (*Plugin)(nil)
	_ plugins.SchemaProvider        = (*Plugin)(nil)
	_ plugins.EndpointHooksProvider = (*Plugin)(nil)
)

// pluginOptions are the plugin-wide options.
type pluginOptions struct {
	deps  services.Deps
	names config.SchemaOptions
}

// Option configures the plugin.
type Option func(*pluginOptions)

// WithSchema renames the apikey table and its columns (better-auth's `schema` option).
func WithSchema(s config.SchemaOptions) Option {
	return func(o *pluginOptions) { o.names = s }
}

// WithOrganization connects organization-owned keys to the organization plugin (see OrganizationFrom).
func WithOrganization(org OrganizationAuthorizer) Option {
	return func(o *pluginOptions) { o.deps.Organization = org }
}

// WithClock replaces the clock (tests: expiry, refills and rate-limit windows).
func WithClock(now func() time.Time) Option {
	return func(o *pluginOptions) { o.deps.Now = now }
}

// New creates the plugin with one configuration (better-auth's apiKey(options)).
func New(cfg config.Configuration, opts ...Option) *Plugin {
	p, _ := build([]config.Configuration{cfg}, opts)
	return p
}

// NewWithConfigurations creates the plugin with several configurations (better-auth's apiKey([...])).
// Every configuration needs a unique ConfigID; one named "default" (if any) serves requests without
// configId.
func NewWithConfigurations(cfgs []config.Configuration, opts ...Option) (*Plugin, error) {
	return build(cfgs, opts)
}

// build validates the configurations and applies defaults; a validation error is also returned by Init.
func build(cfgs []config.Configuration, opts []Option) (*Plugin, error) {
	p := &Plugin{}
	for _, o := range opts {
		o(&p.opts)
	}
	if len(cfgs) == 0 {
		cfgs = []config.Configuration{{}}
	}
	p.err = config.ValidateConfigurations(cfgs)
	for _, c := range cfgs {
		p.configs = append(p.configs, c.WithDefaults())
	}
	return p, p.err
}

// ID returns "api-key".
func (p *Plugin) ID() string { return PluginID }

// Schema declares the apikey model (better-auth's apiKeySchema). With one configuration the rate-limit
// columns default to its window and maximum.
func (p *Plugin) Schema() schema.PluginSchema {
	// Step 1: column defaults (better-auth uses the single configuration's values)
	window, max := config.DefaultRateLimitTimeWindow.Milliseconds(), int64(config.DefaultRateLimitMaxRequests)
	if len(p.configs) == 1 {
		window = p.configs[0].RateLimit.TimeWindow.Milliseconds()
		max = int64(*p.configs[0].RateLimit.MaxRequests)
	}
	no := schema.Bool(false)
	field := func(name string, f schema.Field) schema.Field {
		f.FieldName = p.opts.names.Fields[name]
		if f.Input == nil {
			f.Input = no
		}
		return f
	}
	// Step 2: the fields, in better-auth's order
	fields := map[string]schema.Field{
		services.FieldConfigID:            field(services.FieldConfigID, schema.Field{Type: schema.String, Required: true, Default: config.DefaultConfigID, Index: true}),
		services.FieldName:                field(services.FieldName, schema.Field{Type: schema.String}),
		services.FieldStart:               field(services.FieldStart, schema.Field{Type: schema.String}),
		services.FieldReferenceID:         field(services.FieldReferenceID, schema.Field{Type: schema.String, Required: true, Index: true}),
		services.FieldPrefix:              field(services.FieldPrefix, schema.Field{Type: schema.String}),
		services.FieldKey:                 field(services.FieldKey, schema.Field{Type: schema.String, Required: true, Index: true}),
		services.FieldRefillInterval:      field(services.FieldRefillInterval, schema.Field{Type: schema.Number}),
		services.FieldRefillAmount:        field(services.FieldRefillAmount, schema.Field{Type: schema.Number}),
		services.FieldLastRefillAt:        field(services.FieldLastRefillAt, schema.Field{Type: schema.Date}),
		services.FieldEnabled:             field(services.FieldEnabled, schema.Field{Type: schema.Boolean, Default: true}),
		services.FieldRateLimitEnabled:    field(services.FieldRateLimitEnabled, schema.Field{Type: schema.Boolean, Default: true}),
		services.FieldRateLimitTimeWindow: field(services.FieldRateLimitTimeWindow, schema.Field{Type: schema.Number, Default: float64(window)}),
		services.FieldRateLimitMax:        field(services.FieldRateLimitMax, schema.Field{Type: schema.Number, Default: float64(max)}),
		services.FieldRequestCount:        field(services.FieldRequestCount, schema.Field{Type: schema.Number, Default: float64(0)}),
		services.FieldRemaining:           field(services.FieldRemaining, schema.Field{Type: schema.Number}),
		services.FieldLastRequest:         field(services.FieldLastRequest, schema.Field{Type: schema.Date}),
		services.FieldExpiresAt:           field(services.FieldExpiresAt, schema.Field{Type: schema.Date}),
		services.FieldCreatedAt:           field(services.FieldCreatedAt, schema.Field{Type: schema.Date, Required: true}),
		services.FieldUpdatedAt:           field(services.FieldUpdatedAt, schema.Field{Type: schema.Date, Required: true}),
		services.FieldPermissions:         field(services.FieldPermissions, schema.Field{Type: schema.String}),
		services.FieldMetadata:            field(services.FieldMetadata, schema.Field{Type: schema.String, Input: schema.Bool(true)}),
	}
	return schema.PluginSchema{services.ModelName: schema.Model{ModelName: p.opts.names.ModelName, Fields: fields}}
}

// Init builds the service and mounts the endpoints.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return errors.New("api-key: init context is required")
	}
	if p.err != nil {
		return p.err
	}
	// Step 1: shared plugin runtime (sessions, cookies, origin check)
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	p.kit = kit
	// Step 2: storage: the adapter for database keys, the secondary storage for the others
	for _, c := range p.configs {
		if (c.Storage == config.StorageDatabase || c.FallbackToDatabase) && ictx.Adapter == nil {
			return errors.New("api-key: database storage needs goauth's adapter (InitContext.Adapter)")
		}
		if c.Storage == config.StorageSecondary && c.CustomStorage == nil && ictx.SecondaryStorage == nil {
			return errors.New("api-key: storage \"secondary-storage\" needs GoAuthOptions.SecondaryStorage or CustomStorage")
		}
	}
	deps := p.opts.deps
	deps.Configurations = p.configs
	deps.Adapter = ictx.Adapter
	deps.Store = ictx.SecondaryStorage
	deps.Users = ictx.IAuthRepos
	deps.Conf = ictx.Config
	if deps.GenerateID == nil {
		deps.GenerateID = ictx.GenerateID
	}
	p.service = services.New(deps)
	// Step 3: the endpoints
	p.handler = humaapikey.NewHandler(p.service, kit)
	humaapikey.RegisterRoutes(ictx.Api, kit, p.handler)
	return nil
}

// EndpointHooks returns better-auth's before hook that turns a valid API key header into a session on
// every goauth route (only when a configuration enables EnableSessionForAPIKeys).
func (p *Plugin) EndpointHooks() endpointhooks.Hooks {
	if p.service == nil || !p.sessionsEnabled() {
		return endpointhooks.Hooks{}
	}
	return endpointhooks.Hooks{Before: []endpointhooks.BeforeHook{{
		Matcher: func(c *endpointhooks.Context) bool {
			_, _, ok := p.service.FindSessionKey(hookRequest(c))
			return ok
		},
		Handler: p.sessionHook,
	}}}
}

// sessionsEnabled reports whether a configuration mocks sessions from API keys.
func (p *Plugin) sessionsEnabled() bool {
	for _, c := range p.configs {
		if c.EnableSessionForAPIKeys {
			return true
		}
	}
	return false
}

// hookRequest returns the request a hook sees, with the headers earlier hooks may have changed.
func hookRequest(c *endpointhooks.Context) *http.Request {
	if c.Request == nil {
		return &http.Request{Header: c.Headers}
	}
	r := c.Request.Clone(c.Ctx)
	r.Header = c.Headers
	return r
}

// sessionHook is better-auth's API-key before hook: the request runs with the key owner's (mocked)
// session; GET /get-session answers with it.
func (p *Plugin) sessionHook(c *endpointhooks.Context) (*endpointhooks.Response, error) {
	// Step 1: the key and its configuration
	r := hookRequest(c)
	key, cfg, ok := p.service.FindSessionKey(r)
	if !ok {
		return nil, nil
	}
	// Step 2: validate it and mock the owner's session
	auth, err := p.service.AuthenticateKey(c.Ctx, r, key, cfg, services.AuthenticateOptions{RequireUser: true})
	if err != nil {
		return errorResponse(err)
	}
	// Step 3: every later middleware and the endpoint see the session
	c.Ctx = withAuth(c.Ctx, auth)
	if c.Path == "/get-session" {
		return endpointhooks.JSON(http.StatusOK, auth.Session), nil
	}
	return nil, nil
}

// errorResponse answers a hook / middleware error with better-auth's body (RATE_LIMITED carries
// details.tryAgainIn); other errors are returned as is.
func errorResponse(err error) (*endpointhooks.Response, error) {
	body, status, ok := services.ErrorBody(err)
	if !ok || status >= http.StatusInternalServerError {
		return nil, err
	}
	return endpointhooks.JSON(status, body), nil
}

// ─── Request context ─────────────────────────────────────────────────────────

type keyCtxKey struct{}

// withAuth attaches an API-key authentication to ctx: the key (FromContext) and, for user keys, the
// session for goauth's session middlewares, pluginkit routes and the claims-based middlewares.
func withAuth(ctx context.Context, auth *services.KeyAuth) context.Context {
	ctx = context.WithValue(ctx, keyCtxKey{}, auth.Key)
	if auth.Session == nil {
		return ctx
	}
	sw := auth.Session
	ctx = humaadapter.WithSession(ctx, sw)
	claims := token.CustomClaims{UserID: sw.User.ID, SessionID: sw.Session.ID, Role: sw.User.Role, Type: token.TypeAccess,
		ExpiresAt: sessionExpiry(sw)}
	ctx = context.WithValue(ctx, consts.CtxClaims.Str(), claims)
	ctx = context.WithValue(ctx, consts.CTXUser_ID.Str(), sw.User.ID)
	return ctx
}

// sessionExpiry returns the session's expiry as Unix seconds.
func sessionExpiry(sw *dtos.SessionWithUser) int64 {
	return time.Time(sw.Session.ExpiresAt).Unix()
}

// FromContext returns the API key that authenticated the request (session hook or middleware).
func FromContext(ctx context.Context) (*APIKey, bool) {
	k, ok := ctx.Value(keyCtxKey{}).(*APIKey)
	return k, ok && k != nil
}

// SessionFromContext returns the session mocked for the API key's owner (nil for organization keys).
func SessionFromContext(ctx context.Context) (*dtos.SessionWithUser, bool) {
	if _, ok := FromContext(ctx); !ok {
		return nil, false
	}
	return humaadapter.FromContext(ctx)
}

// ─── Middleware for your own routes ──────────────────────────────────────────

// MiddlewareOptions tune Middleware / HTTPMiddleware.
type MiddlewareOptions struct {
	// Optional lets requests without an API key through (unauthenticated); a key that is present must still
	// be valid.
	Optional bool
	// Permissions the key must grant ({resource: [actions]}); otherwise 401 KEY_NOT_FOUND.
	Permissions map[string][]string
	// ConfigID accepts only keys of this configuration (default: the first configuration whose header
	// carries a key).
	ConfigID string
}

// authenticate checks the request's API key for a host route: (nil, nil) when there is none. Without
// MiddlewareOptions.ConfigID a key is accepted from any configuration: every storage backend whose header
// carries a key is searched, and the key's own configuration applies.
func (p *Plugin) authenticate(r *http.Request, o MiddlewareOptions) (*services.KeyAuth, error) {
	if p.service == nil {
		return nil, errors.New("api-key: plugin is not initialized")
	}
	var notFound error
	searched := map[string]bool{}
	for _, c := range p.configs {
		// Step 1: the configurations allowed, whose header (or getter) carries a key, once per storage
		if o.ConfigID != "" && !config.ConfigIDMatches(c.ConfigID, o.ConfigID) {
			continue
		}
		key := services.KeyFromRequest(r, c)
		if key == "" {
			continue
		}
		backend := services.StorageIdentifier(c)
		if searched[backend] {
			continue
		}
		searched[backend] = true
		// Step 2: validate it like the session hook (organization keys pass without a session)
		auth, err := p.service.AuthenticateKey(r.Context(), r, key, c, services.AuthenticateOptions{
			Permissions: o.Permissions, AnyConfig: o.ConfigID == "",
		})
		if ae := autherr.AsAuthError(err); ae != nil && ae.Code == services.ErrInvalidAPIKey.Code && ae.StatusCode == http.StatusUnauthorized {
			// not stored in this backend: try the next one
			notFound = err
			continue
		}
		return auth, err
	}
	return nil, notFound
}

// Middleware authenticates Huma routes of your own by API key (APIKeyHeaders / CustomAPIKeyGetter of the
// configurations), whether or not EnableSessionForAPIKeys is set: the key's use is recorded (remaining,
// rate limit) and the request context carries the key (FromContext) and, for user keys, the owner's
// session (SessionFromContext, goauth's session middlewares and authenticator.SessionFromContext).
// Without a key it answers 401 UNAUTHORIZED unless Optional; invalid keys get better-auth's errors.
func (p *Plugin) Middleware(o MiddlewareOptions) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// Step 1: the request as net/http sees it
		u := ctx.URL()
		r, err := http.NewRequestWithContext(ctx.Context(), ctx.Method(), u.String(), nil)
		if err != nil {
			writeHumaError(ctx, err)
			return
		}
		ctx.EachHeader(func(name, value string) { r.Header.Add(name, value) })
		r.RemoteAddr = ctx.RemoteAddr()
		// Step 2: authenticate
		auth, err := p.authenticate(r, o)
		if err != nil {
			writeHumaError(ctx, err)
			return
		}
		if auth == nil {
			if !o.Optional {
				writeHumaError(ctx, unauthorized())
				return
			}
			next(ctx)
			return
		}
		next(huma.WithContext(ctx, withAuth(ctx.Context(), auth)))
	}
}

// HTTPMiddleware is Middleware for net/http handlers.
func (p *Plugin) HTTPMiddleware(o MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth, err := p.authenticate(r, o)
			if err != nil {
				writeHTTPError(w, err)
				return
			}
			if auth == nil {
				if !o.Optional {
					writeHTTPError(w, unauthorized())
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(withAuth(r.Context(), auth)))
		})
	}
}

// unauthorized is the error for a missing key (better-auth's sessionMiddleware 401).
func unauthorized() error {
	return pluginkit.NewError(http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
}

// errorJSON returns the status and body of an error (internal errors are hidden).
func errorJSON(err error) (int, []byte) {
	body, status, ok := services.ErrorBody(err)
	if !ok || status >= http.StatusInternalServerError {
		status, body = http.StatusInternalServerError, map[string]any{"code": "INTERNAL_SERVER_ERROR", "message": "Internal Server Error"}
	}
	raw, _ := json.Marshal(body)
	return status, raw
}

func writeHumaError(ctx huma.Context, err error) {
	status, raw := errorJSON(err)
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetStatus(status)
	_, _ = ctx.BodyWriter().Write(raw)
}

func writeHTTPError(w http.ResponseWriter, err error) {
	status, raw := errorJSON(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// ─── Server-side Go API (better-auth's auth.api.* without headers) ───────────

// CreateAPIKey creates a key as the server (server-only fields allowed). in.UserID names the owner
// (in.OrganizationID plus the acting in.UserID for organization keys).
func (p *Plugin) CreateAPIKey(ctx context.Context, in CreateAPIKeyInput) (*CreateAPIKeyResponse, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	return p.service.Create(ctx, in, services.Call{})
}

// VerifyAPIKey is better-auth's server-only verifyApiKey: it validates a key (and the permissions asked
// for), records its use and returns {valid, error, key}. The error return is only set when the
// configuration cannot be resolved.
func (p *Plugin) VerifyAPIKey(ctx context.Context, in VerifyAPIKeyInput) (*VerifyAPIKeyResult, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	return p.service.Verify(ctx, in)
}

// GetAPIKey returns key id of user userID (configID selects the configuration, "" = default).
func (p *Plugin) GetAPIKey(ctx context.Context, id, configID, userID string) (*APIKeyResponse, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	if userID == "" {
		return nil, services.ErrUnauthorizedSession
	}
	return p.service.Get(ctx, id, configID, userID)
}

// UpdateAPIKey updates a key as the server (server-only fields allowed); in.UserID must own the key.
func (p *Plugin) UpdateAPIKey(ctx context.Context, in UpdateAPIKeyInput) (*APIKeyResponse, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	return p.service.Update(ctx, in, services.Call{})
}

// DeleteAPIKey deletes key keyID of user userID (banned users get USER_BANNED, like the endpoint).
func (p *Plugin) DeleteAPIKey(ctx context.Context, keyID, configID, userID string) error {
	if err := p.ready(); err != nil {
		return err
	}
	if userID == "" {
		return services.ErrUnauthorizedSession
	}
	user := &dtos.UserResponse{ID: userID}
	if u, err := p.kit.Repos.FindUserByID(ctx, userID); err == nil && u != nil {
		resp := dtos.UserFromModel(u)
		user = &resp
	}
	return p.service.Delete(ctx, keyID, configID, user)
}

// ListAPIKeysInput is the input of ListAPIKeys.
type ListAPIKeysInput = services.ListInput

// ListAPIKeys lists the keys of user userID (or of in.OrganizationID, which the user must be allowed to
// read).
func (p *Plugin) ListAPIKeys(ctx context.Context, userID string, in ListAPIKeysInput) (*ListAPIKeysResult, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	if userID == "" {
		return nil, services.ErrUnauthorizedSession
	}
	return p.service.List(ctx, in, userID)
}

// DeleteAllExpiredAPIKeys is better-auth's server-only deleteAllExpiredApiKeys: it removes every expired
// database key now.
func (p *Plugin) DeleteAllExpiredAPIKeys(ctx context.Context) error {
	if err := p.ready(); err != nil {
		return err
	}
	return p.service.DeleteAllExpiredNow(ctx).Error
}

// ready fails before Init.
func (p *Plugin) ready() error {
	if p.service == nil {
		if p.err != nil {
			return p.err
		}
		return errors.New("api-key: plugin is not initialized (pass it to goauth.SetupGoAuth)")
	}
	return nil
}

// HashKey is better-auth's defaultKeyHasher (SHA-256, base64url without padding).
func HashKey(key string) string { return services.HashKey(key) }

// Migrator returns nil: the apikey table comes from the plugin schema.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services exposes the service.
func (p *Plugin) Services() map[string]any { return map[string]any{"apiKey": p.service} }

// Routes returns nil: routes are mounted on Huma in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor { return nil }

// Service returns the service (nil before Init).
func (p *Plugin) Service() *services.Service { return p.service }

// Configurations returns the effective configurations.
func (p *Plugin) Configurations() []config.Configuration { return p.configs }
