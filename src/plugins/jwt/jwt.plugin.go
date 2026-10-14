package jwt

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"strings"
	"time"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	humajwt "github.com/better-go-auth/goauth/src/plugins/jwt/adapters/huma"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	jwtmodels "github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"github.com/better-go-auth/goauth/src/plugins/jwt/repository"
	"github.com/better-go-auth/goauth/src/plugins/jwt/services"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"gorm.io/gorm"
)

const PluginID = "jwt"

// Plugin implements plugins.Plugin for Better Auth's JWT and JWKS specification.
type Plugin struct {
	config   jwtconfig.JWTConfig
	db       *gorm.DB
	repo     repository.IJwksRepo
	service  *services.JWTService
	handler  *humajwt.JWTHandler
	resolver *humaadapter.Resolver
	basePath string
}

var _ plugins.Plugin = (*Plugin)(nil)

// Option configures the JWT Plugin.
type Option func(*Plugin)

// WithDB sets the GORM database connection for the JWT plugin.
func WithDB(db *gorm.DB) Option {
	return func(p *Plugin) {
		p.db = db
	}
}

// WithRepo sets a custom repository implementation for JWKS.
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

// WithBasePath configures the auth base path (default: "/api/auth").
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
	if cfg.Jwks.KeyPairConfig.Crv == "" {
		cfg.Jwks.KeyPairConfig.Crv = defaultCfg.Jwks.KeyPairConfig.Crv
	}

	p := &Plugin{
		config:   cfg,
		basePath: "/api/auth",
	}
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

// Migrator returns the database migrator for creating the jwks table.
func (p *Plugin) Migrator() migration.IMigrator {
	if p.db != nil {
		return jwtmodels.NewMigrator(p.db)
	}
	return nil
}

// Services returns the services provided by this plugin.
func (p *Plugin) Services() map[string]any {
	return map[string]any{
		"jwt": p.service,
	}
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

	if p.db == nil && ictx.Extras != nil {
		if dbVal, ok := ictx.Extras["db"].(*gorm.DB); ok && dbVal != nil {
			p.db = dbVal
		}
	}

	if p.repo == nil {
		if p.db == nil {
			return fmt.Errorf("jwt plugin: *gorm.DB is required to create jwks repository")
		}
		p.repo = repository.NewGormJwksRepo(p.db)
	}

	secret := ictx.Config.Secret
	baseURL := ictx.Config.BaseURL

	p.service = services.NewJWTService(p.config, secret, baseURL, p.repo)

	cm := cookies.New(ictx.Config)
	var sessMgr *sessionsvc.Manager
	if sm, ok := ictx.SessionManager.(*sessionsvc.Manager); ok {
		sessMgr = sm
	} else if ictx.Extras != nil {
		if smVal, ok := ictx.Extras["sessionManager"].(*sessionsvc.Manager); ok {
			sessMgr = smVal
		}
	}
	p.resolver = humaadapter.NewResolver(sessMgr, cm)

	p.handler = humajwt.NewJWTHandler(p.service, p.resolver)

	humajwt.RegisterRoutes(ictx.Api, p.basePath, p.config.Jwks.JwksPath, p.handler)

	// Register middleware for setting set-auth-jwt response header on /get-session (after hook)
	if !p.config.DisableSettingJwtHeader {
		ictx.Api.UseMiddleware(p.afterGetSessionMiddleware(ictx.Config))
	}

	return nil
}

func (p *Plugin) afterGetSessionMiddleware(authCfg config.AuthConfig) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		path := ctx.URL().Path
		isSessionRoute := strings.EqualFold(path, "/get-session") ||
			strings.HasSuffix(strings.ToLower(path), "/get-session") ||
			strings.EqualFold(path, "/session") ||
			strings.HasSuffix(strings.ToLower(path), "/session")

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

						if _, hw := humago.Unwrap(ctx); hw != nil {
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
