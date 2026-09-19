package plugins

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers/authenticator"

	// "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"github.com/danielgtaylor/huma/v2"
)

// InitContext carries runtime dependencies and configuration passed to plugins during initialization.
type InitContext struct {
	Ctx    context.Context
	Api    huma.API
	Config config.AuthConfig
	// UserRepo    repoimpl2.IUserRepo
	// SessionRepo repoimpl2.ISessionRepo
	// EmailSender emailiface.IVerificationSender
	TxManager     interfaces.ITransactionManager
	IAuthServices serv_interfaces.IAuthServices
	IAuthRepos    repo_interfaces.IAuthRepos
	MiddleWare    *middleware.AuthMiddleware
	Authenticate  authenticator.AuthenticateFunc
	Hooks         HookRegistry

	// Extras allows plugins that need ORM-specific objects (e.g. *gorm.DB) to
	// receive them without coupling the interface to any particular ORM.
	// The host application populates this map before calling plugin.Init.
	Extras map[string]any
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
