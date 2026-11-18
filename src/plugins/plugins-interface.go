package plugins

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/adapter"
	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	"github.com/better-go-auth/goauth/src/models/dtos"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	// "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/better-go-auth/goauth/src/providers/cookies"
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

	// Adapter is the storage-agnostic adapter over the schema registry (core + config + plugin schemas).
	// It is nil until SetupGoAuth builds the registry and adapter (missing-tasks 2.5); plugins moving off
	// DB (2.9) read and write their models through it with registry field names.
	Adapter adapter.Adapter

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

// SchemaFieldsProvider is an optional interface for plugins that add fields to better-auth's user or
// session schema (e.g. admin: role, banned, ...). Like better-auth, the user/session JSON always contains
// the fields of installed plugins (false / null when unset), and update-user knows which keys exist.
type SchemaFieldsProvider interface {
	SchemaFields() dtos.SchemaFields
}

// SchemaProvider is an optional interface for plugins that declare database schema like better-auth's
// plugin `schema`: fields added to existing models (user, session, ...) and whole new models (tables).
// SetupGoAuth merges every provider into the schema registry after the configuration's additionalFields
// (later plugins win), and the registry drives input parsing, output, migrations and the adapter.
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
