package plugins

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/adapter"
	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/dbhooks"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	// "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/danielgtaylor/huma/v2"
	"gorm.io/gorm"
)

// InitContext carries runtime dependencies and configuration passed to plugins during initialization.
type InitContext struct {
	Ctx    context.Context
	Api    huma.API
	Config config.AuthConfig
	// UserRepo    repoimpl2.IUserRepo
	// SessionRepo repoimpl2.ISessionRepo
	// EmailSender emailiface.IVerificationSender
	TxManager interfaces.ITransactionManager
	// Auth services
	SessionManager svcint.ISessionManager
	IAuthSvc       svcint.IAuthService
	// INormalAuthServices serv_interfaces.INormalAuthServices
	// ILegacyAuthServices serv_interfaces.ILegacyAuthServices
	//
	IAuthRepos       repo_interfaces.IAuthRepos
	MiddleWare       *middleware.AuthMiddleware
	Authenticator    authenticator.AuthenticateFunc
	Hooks            HookRegistry
	SecondaryStorage sec_storage.SecondaryStorage
	DB               *gorm.DB
	CookieManager    *cookies.Manager
	GenerateID       func() string
	// RateLimiter is goauth's one rate limiter (AuthConfig.RateLimit). Plugins add rules with
	// RateLimitProvider (or pluginkit.Route.RateLimit); nil outside SetupGoAuth.
	RateLimiter *ratelimit.Limiter

	// Adapter is the storage-agnostic adapter over the schema registry (core + config + plugin schemas):
	// records keyed by registry field names, on GoAuthOptions.Conn (GORM) or the adapter behind
	// adapter-based Repositories. Plugins that declare tables with SchemaProvider read and write them through
	// it (their tables are created by goauth's migrator). nil only when GoAuthOptions.Repositories is not
	// adapter-based and there is no Conn.
	Adapter adapter.Adapter
	// Schema is the schema registry SetupGoAuth built (core models, configuration additionalFields and
	// renames, every SchemaProvider): table and column names, field definitions, input/output rules.
	Schema *schema.Registry
	// Internal is goauth's internalAdapter (better-auth's ctx.context.internalAdapter): create, update and
	// delete users, sessions, accounts and verifications with database hooks, additionalFields and secondary
	// storage applied. Plugins use it instead of writing through IAuthRepos directly.
	Internal svcint.IInternalAdapter
	// Plugin returns the installed plugin with id, or nil (better-auth's ctx.context.getPlugin). Plugins are
	// initialized one after the other, so call it at request time (or after Init) to see every plugin; nil
	// outside SetupGoAuth.
	Plugin func(id string) Plugin
	// Plugins are every plugin SetupGoAuth installs (including the social plugin it adds for
	// AuthConfig.SocialProviders), in configuration order: better-auth's ctx.context.hasPlugin / getPlugin.
	// A plugin may keep the slice and look its siblings up at request time (they may initialize after it),
	// e.g. FindOrganizationStore. nil outside SetupGoAuth.
	Plugins []Plugin

	// Extras is intentionally disabled. We do not use this field; all
	// dependencies are provided via the typed fields above (DB,
	// CookieManager, SecondaryStorage, SessionManager, etc.).
	// Only re-enable with explicit justification and a typed alternative
	// if a genuine need arises that cannot be modelled otherwise.
	// Extras map[string]any
}

// Plugin defines the interface that all better-go-auth plugins (e.g. Org, 2FA, Passkeys) must implement.
type Plugin interface {
	// ID returns the unique string identifier for the plugin (e.g., "org").
	ID() string

	// Init initializes the plugin's repositories, migrators, and services using the provided InitContext.
	Init(ictx *InitContext) error

	// Migrator returns the database migrator for this plugin, if any.
	Migrator() migration.IMigrator

	// Services returns a map of services provided by this plugin.
	Services() map[string]any

	// Routes returns a slice of framework-agnostic route descriptors.
	// Adapters iterate over this slice to mount plugin routes.
	// Return nil if the plugin does not expose any routes (or uses a
	// framework-specific setup method instead).
	Routes() []RouteDescriptor
}

// DependencyProvider is an optional interface for plugins that only work when other plugins are
// installed too. SetupGoAuth fails when one of the returned plugin IDs is missing from Plugins.
type DependencyProvider interface {
	Dependencies() []string
}

// DatabaseHooksProvider is an optional interface for plugins with better-auth database hooks (a plugin's
// `init` returning `options.databaseHooks`): before/after hooks on creates, updates and deletes of users,
// sessions, accounts and verifications, whoever writes them. SetupGoAuth collects them after the plugin's
// Init, in plugin order, and runs them before AuthConfig.DatabaseHooks (better-auth's order).
type DatabaseHooksProvider interface {
	DatabaseHooks() dbhooks.Hooks
}

// SchemaProvider is an optional interface for plugins that declare database schema like better-auth's
// plugin `schema`: fields added to existing models (user, session, ...) and whole new models (tables).
// SetupGoAuth merges every provider into the schema registry after the configuration's additionalFields
// (later plugins win), and the registry drives input parsing, output, migrations and the adapter.
//
// Schema is called before Init (the registry is built first), so it may only depend on the plugin's
// options. Tables declared here are created by goauth's migrator (GoAuth.Migrations.Mode auto), checked
// by verify mode and included in goauth.GenerateSQL / the goauth CLI; the plugin reads and writes them
// with InitContext.Adapter and needs no Migrator.
type SchemaProvider interface {
	Schema() schema.PluginSchema
}

// HookProvider is an optional interface plugins can implement to provide a HookService.
type HookProvider interface {
	Hooks() HookService
}

// RouteDescriptor describes a single HTTP route exposed by a plugin in a
// framework-agnostic way. Framework adapters (Gin, Fiber, Huma, …) read this
// slice and mount the routes using their own registration API.
type RouteDescriptor struct {
	// Method is the HTTP method (e.g. "GET", "POST").
	Method string
	// Path is the route path relative to the auth BasePath (e.g. "/org/create").
	Path string
	// Handler is a standard net/http handler. Framework adapters wrap or convert
	// this as needed.
	Handler http.HandlerFunc
	// Description is a human-readable summary used for OpenAPI / docs generation.
	Description string
	// Tags groups routes for documentation (e.g. ["org", "admin"]).
	Tags []string
	// Middlewares lists named middleware to apply (e.g. "auth", "admin").
	// Adapters resolve these names to their own middleware implementations.
	Middlewares []string
}
