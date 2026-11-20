package jwt

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humajwt "github.com/better-go-auth/goauth/src/plugins/jwt/adapters/huma"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	jwtmodels "github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"github.com/better-go-auth/goauth/src/plugins/jwt/repository"
	"github.com/better-go-auth/goauth/src/plugins/jwt/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

func safeHumagoUnwrap(ctx huma.Context) (r *http.Request, w http.ResponseWriter) {
	defer func() {
		_ = recover()
	}()
	return humago.Unwrap(ctx)
}

const PluginID = "jwt"

// Plugin implements plugins.Plugin for Better Auth's JWT and JWKS specification.
type Plugin struct {
	config   jwtconfig.JWTConfig
	repo     repository.IJwksRepo
	service  *services.JWTService
	handler  *humajwt.JWTHandler
	resolver *humaadapter.Resolver
	basePath string
}

var (
	_ plugins.Plugin         = (*Plugin)(nil)
	_ plugins.SchemaProvider = (*Plugin)(nil)
)

// Option configures the JWT Plugin.
type Option func(*Plugin)

// WithRepo sets a custom repository implementation for JWKS (default: the jwks table through
// InitContext.Adapter).
func WithRepo(repo repository.IJwksRepo) Option {
	return func(p *Plugin) {
		p.repo = repo
	}
}

// WithConfig sets the entire JWTConfig.
func WithConfig(cfg jwtconfig.JWTConfig) Option {
	return func(p *Plugin) {
		p.config = cfg
	}
}

// WithJwksPath customizes the path where JWKS is exposed (default: "/jwks").
func WithJwksPath(path string) Option {
	return func(p *Plugin) {
		p.config.Jwks.JwksPath = path
	}
}

// WithExpirationTime sets the expiration time for issued JWTs (default: 15 minutes).
func WithExpirationTime(d time.Duration) Option {
	return func(p *Plugin) {
		p.config.JWT.ExpirationTime = d
	}
}

// WithIssuer sets the "iss" claim.
func WithIssuer(issuer string) Option {
	return func(p *Plugin) {
		p.config.JWT.Issuer = issuer
	}
}

// WithAudience sets the "aud" claim.
func WithAudience(aud string) Option {
	return func(p *Plugin) {
		p.config.JWT.Audience = aud
	}
}

// WithDisableSettingJwtHeader disables setting the set-auth-jwt response header on session retrieval.
func WithDisableSettingJwtHeader(disable bool) Option {
	return func(p *Plugin) {
		p.config.DisableSettingJwtHeader = disable
	}
}

// WithBasePath mounts the JWT routes under another base path than the core routes (default: the core
// AuthConfig.BasePath).
func WithBasePath(basePath string) Option {
	return func(p *Plugin) {
		p.basePath = basePath
	}
}

// New creates a new JWT plugin instance.
// Directly accepts the config struct so users can configure it directly (matching Better Auth's pattern),
// with functional options supported as additional optional overrides.
func New(cfg jwtconfig.JWTConfig, opts ...Option) *Plugin {
	defaultCfg := jwtconfig.DefaultConfig()
	if cfg.Jwks.JwksPath == "" {
		cfg.Jwks.JwksPath = defaultCfg.Jwks.JwksPath
	}
	if cfg.Jwks.GracePeriod <= 0 {
		cfg.Jwks.GracePeriod = defaultCfg.Jwks.GracePeriod
	}
	if cfg.JWT.ExpirationTime <= 0 {
		cfg.JWT.ExpirationTime = defaultCfg.JWT.ExpirationTime
	}
	if cfg.Jwks.KeyPairConfig.Alg == "" {
		cfg.Jwks.KeyPairConfig.Alg = defaultCfg.Jwks.KeyPairConfig.Alg
	}
	// Crv (and the RSA modulus length) default per algorithm; Init validates the combination
	if cfg.Jwks.KeyPairConfig.Crv == "" && cfg.Jwks.KeyPairConfig.Alg == jwtconfig.AlgEdDSA {
		cfg.Jwks.KeyPairConfig.Crv = jwtconfig.CrvEd25519
	}

	p := &Plugin{config: cfg}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ID returns the unique plugin identifier.
func (p *Plugin) ID() string {
	return PluginID
}

// SetDB allows setting the database connection prior to migration.
// func (p *Plugin) SetDB(db *gorm.DB) {
// 	p.db = db
// }

// Schema declares better-auth's jwks table (plugins.SchemaProvider); goauth's migrator creates it.
func (p *Plugin) Schema() schema.PluginSchema { return jwtmodels.Schema() }

// Migrator returns nil: the jwks table is declared by Schema and created by goauth's migrator.
func (p *Plugin) Migrator() migration.IMigrator { return nil }

// Services returns the services provided by this plugin.
func (p *Plugin) Services() map[string]any {
	return map[string]any{
		"jwt": p.service,
	}
}

// SignJWTOptions overrides the plugin's issuer, audience or lifetime for one SignJWT call.
type SignJWTOptions = services.SignJWTOptions

// Service returns the plugin's JWT service (key management, signing and verification).
// It is nil until the plugin has been initialized by goauth.SetupGoAuth.
func (p *Plugin) Service() *services.JWTService {
	return p.service
}

// SignJWT signs payload with the active key pair and returns the compact JWT. It is the Go equivalent of
// better-auth's server-only auth.api.signJWT and is not exposed over HTTP. Missing iat, exp, iss and aud
// claims are filled in from the plugin configuration or opts (which may be nil).
func (p *Plugin) SignJWT(ctx context.Context, payload map[string]any, opts *SignJWTOptions) (string, error) {
	if p.service == nil {
		return "", fmt.Errorf("jwt plugin: not initialized")
	}
	return p.service.SignJWT(ctx, payload, opts)
}

// VerifyJWT verifies a JWT signed by this plugin (signature, exp, iss, aud and sub) and returns its
// claims. It is the Go equivalent of better-auth's server-only auth.api.verifyJWT. issuer overrides the
// expected "iss" claim ("" uses the configured issuer, then the base URL).
func (p *Plugin) VerifyJWT(ctx context.Context, token, issuer string) (map[string]any, error) {
	if p.service == nil {
		return nil, fmt.Errorf("jwt plugin: not initialized")
	}
	return p.service.VerifyJWT(ctx, token, issuer)
}

// Config returns the plugin's configuration (better-auth's jwtPlugin.options), e.g. for the oidc-provider
// plugin, which takes its issuer from JWT.Issuer.
func (p *Plugin) Config() jwtconfig.JWTConfig {
	return p.config
}

// Routes returns nil as routes are mounted via Huma API in Init.
func (p *Plugin) Routes() []plugins.RouteDescriptor {
	return nil
}

// Init initializes repositories, services, route handlers, and middleware.
func (p *Plugin) Init(ictx *plugins.InitContext) error {
	if ictx == nil {
		return fmt.Errorf("jwt plugin: init context is required")
	}

	// Reject an unsupported key algorithm up front instead of on the first signed token
	kp, err := p.config.Jwks.KeyPairConfig.Normalize()
	if err != nil {
		return fmt.Errorf("jwt plugin: %w", err)
	}
	p.config.Jwks.KeyPairConfig = kp

	if p.repo == nil {
		if ictx.Adapter == nil {
			return fmt.Errorf("jwt plugin: a storage adapter (GoAuthOptions.Conn or adapter-based Repositories) or WithRepo is required")
		}
		repo, err := repository.New(ictx.Adapter, ictx.Schema)
		if err != nil {
			return fmt.Errorf("jwt plugin: %w", err)
		}
		p.repo = repo
	}

	keys := authcrypto.NewSecretKeys(ictx.Config)
	baseURL := ictx.Config.BaseURL

	p.service = services.NewJWTServiceWithKeys(p.config, keys, baseURL, p.repo)

	// shared plugin runtime: goauth's one session resolver and cookie manager, base path, disabled routes
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return fmt.Errorf("jwt plugin: %w", err)
	}
	if p.basePath != "" {
		kit.BasePath = strings.TrimSuffix(p.basePath, "/")
	}
	p.basePath = kit.BasePath
	p.resolver = kit.Resolver

	p.handler = humajwt.NewJWTHandler(p.service, kit)

	humajwt.RegisterRoutes(ictx.Api, kit, p.config.Jwks.JwksPath, p.handler)

	// Register middleware for setting set-auth-jwt response header on /get-session (after hook)
	if !p.config.DisableSettingJwtHeader {
		ictx.Api.UseMiddleware(p.afterGetSessionMiddleware(ictx.Config))
	}

	return nil
}

func (p *Plugin) afterGetSessionMiddleware(authCfg config.AuthConfig) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		path := strings.ToLower(ctx.URL().Path)
		base := strings.ToLower(strings.TrimSuffix(p.basePath, "/"))
		if base == "" {
			base = "/api/auth"
		}
		isSessionRoute := path == base+"/get-session" || path == base+"/session"

		if !isSessionRoute {
			next(ctx)
			return
		}

		wrapped := &jwtContextWrapper{
			inner: ctx,
			onBeforeWrite: func() {
				if p.config.DisableSettingJwtHeader || p.service == nil || p.resolver == nil {
					return
				}
				session, _ := humaadapter.FromContext(ctx.Context())
				if session == nil {
					cookieHdr := ctx.Header("Cookie")
					if s, err := p.resolver.Resolve(ctx.Context(), cookieHdr); err == nil && s != nil {
						session = s
					}
				}
				if session != nil {
					jwtTok, err := p.service.GetJWTToken(ctx.Context(), session)
					if err == nil && jwtTok != "" {
						ctx.SetHeader("set-auth-jwt", jwtTok)
						cur := ctx.Header("Access-Control-Expose-Headers")
						ctx.SetHeader("Access-Control-Expose-Headers", appendExposed(cur, "set-auth-jwt"))

						if _, hw := safeHumagoUnwrap(ctx); hw != nil {
							hw.Header().Set("set-auth-jwt", jwtTok)
							curExp := hw.Header().Get("Access-Control-Expose-Headers")
							hw.Header().Set("Access-Control-Expose-Headers", appendExposed(curExp, "set-auth-jwt"))
						}
					}
				}
			},
		}

		next(wrapped)

		// Final check in case SetStatus/BodyWriter wasn't invoked
		wrapped.flush()
	}
}

type jwtContextWrapper struct {
	inner         huma.Context
	onBeforeWrite func()
	wrote         bool
}

var _ huma.Context = (*jwtContextWrapper)(nil)

func (w *jwtContextWrapper) flush() {
	if !w.wrote {
		w.wrote = true
		if w.onBeforeWrite != nil {
			w.onBeforeWrite()
		}
	}
}

func (w *jwtContextWrapper) Unwrap() huma.Context       { return w.inner }
func (w *jwtContextWrapper) Operation() *huma.Operation { return w.inner.Operation() }
func (w *jwtContextWrapper) Context() context.Context   { return w.inner.Context() }
func (w *jwtContextWrapper) TLS() *tls.ConnectionState  { return w.inner.TLS() }
func (w *jwtContextWrapper) Version() huma.ProtoVersion { return w.inner.Version() }
func (w *jwtContextWrapper) Method() string             { return w.inner.Method() }
func (w *jwtContextWrapper) Host() string               { return w.inner.Host() }
func (w *jwtContextWrapper) RemoteAddr() string         { return w.inner.RemoteAddr() }
func (w *jwtContextWrapper) URL() url.URL               { return w.inner.URL() }
func (w *jwtContextWrapper) Param(name string) string   { return w.inner.Param(name) }
func (w *jwtContextWrapper) Query(name string) string   { return w.inner.Query(name) }
func (w *jwtContextWrapper) Header(name string) string  { return w.inner.Header(name) }
func (w *jwtContextWrapper) EachHeader(cb func(name, value string)) {
	w.inner.EachHeader(cb)
}
func (w *jwtContextWrapper) BodyReader() io.Reader { return w.inner.BodyReader() }
func (w *jwtContextWrapper) GetMultipartForm() (*multipart.Form, error) {
	return w.inner.GetMultipartForm()
}
func (w *jwtContextWrapper) SetReadDeadline(t time.Time) error { return w.inner.SetReadDeadline(t) }
func (w *jwtContextWrapper) Status() int                       { return w.inner.Status() }

func (w *jwtContextWrapper) SetStatus(code int) {
	w.flush()
	w.inner.SetStatus(code)
}

func (w *jwtContextWrapper) SetHeader(name, value string) {
	w.inner.SetHeader(name, value)
}

func (w *jwtContextWrapper) AppendHeader(name, value string) {
	w.inner.AppendHeader(name, value)
}

func (w *jwtContextWrapper) BodyWriter() io.Writer {
	w.flush()
	return w.inner.BodyWriter()
}

func appendExposed(current, toAdd string) string {
	if current == "" {
		return toAdd
	}
	parts := strings.Split(current, ",")
	for _, p := range parts {
		if strings.EqualFold(strings.TrimSpace(p), toAdd) {
			return current
		}
	}
	return current + ", " + toAdd
}
