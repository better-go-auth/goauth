package adapters

import (
	"github.com/danielgtaylor/huma/v2"
)

// DocsRenderer constants supported natively by Huma.
const (
	DocsRendererStoplight = "stoplight" // Default Stoplight Elements UI
	DocsRendererScalar    = "scalar"    // Modern Scalar UI
	DocsRendererSwaggerUI = "swagger-ui" // Classic Swagger UI
	DocsRendererRapiDoc   = "rapidoc"   // Fast RapiDoc UI
)

// RouterConfig contains configuration for creating a Huma API instance with optional docs.
type RouterConfig struct {
	// Title is the API title in OpenAPI metadata and docs (default: "Better Go Auth API").
	Title string
	// Version is the API semver version (default: "1.0.0").
	Version string
	// DocsPath is the browser URL path for interactive documentation (default: "/docs").
	DocsPath string
	// OpenAPIPath is the path for OpenAPI specs (default: "/openapi", providing /openapi.json and /openapi.yaml).
	OpenAPIPath string
	// SchemasPath is the path for schema introspection (default: "/schemas").
	SchemasPath string
	// DocsRenderer selects the documentation UI renderer: "stoplight", "scalar", "swagger-ui", "rapidoc".
	DocsRenderer string
	// DocsRendererConfig provides optional renderer-specific configuration (e.g. for Scalar or Swagger UI).
	DocsRendererConfig any
	// EnableDocs explicitly controls whether docs are enabled. When nil, docs default to enabled.
	EnableDocs *bool
	// DisableDocs turns off the interactive documentation endpoint when true.
	DisableDocs bool
	// BaseConfig allows starting from an existing huma.Config.
	BaseConfig *huma.Config
	// Configure allows custom mutation of the huma.Config before API instantiation.
	Configure func(*huma.Config)
}

// Option configures RouterConfig.
type Option func(*RouterConfig)

// DefaultRouterConfig returns standard defaults for Huma router adapters.
func DefaultRouterConfig() RouterConfig {
	return RouterConfig{
		Title:        "Better Go Auth API",
		Version:      "1.0.0",
		DocsPath:     "/docs",
		OpenAPIPath:  "/openapi",
		SchemasPath:  "/schemas",
		DocsRenderer: DocsRendererStoplight,
	}
}

// WithTitle sets the API title in OpenAPI and docs.
func WithTitle(title string) Option {
	return func(c *RouterConfig) {
		if title != "" {
			c.Title = title
		}
	}
}

// WithVersion sets the API version in OpenAPI and docs.
func WithVersion(version string) Option {
	return func(c *RouterConfig) {
		if version != "" {
			c.Version = version
		}
	}
}

// WithEnableDocs dynamically enables or disables the interactive documentation endpoint.
// When enabled is true, docs are served at docsPath (or default "/docs" if omitted).
// When enabled is false, docs are disabled.
func WithEnableDocs(enabled bool, docsPath ...string) Option {
	return func(c *RouterConfig) {
		c.EnableDocs = &enabled
		c.DisableDocs = !enabled
		if !enabled {
			c.DocsPath = ""
			return
		}
		if len(docsPath) > 0 && docsPath[0] != "" {
			c.DocsPath = docsPath[0]
		} else if c.DocsPath == "" {
			c.DocsPath = "/docs"
		}
	}
}

// WithDocs enables interactive docs (default path "/docs", or custom path if specified).
func WithDocs(docsPath ...string) Option {
	return WithEnableDocs(true, docsPath...)
}

// WithoutDocs disables the interactive documentation route.
func WithoutDocs() Option {
	return WithEnableDocs(false)
}

// WithOpenAPIPath sets the path for the OpenAPI spec (e.g. "/openapi").
func WithOpenAPIPath(path string) Option {
	return func(c *RouterConfig) {
		c.OpenAPIPath = path
	}
}

// WithSchemasPath sets the path for JSON schema introspection (e.g. "/schemas").
func WithSchemasPath(path string) Option {
	return func(c *RouterConfig) {
		c.SchemasPath = path
	}
}

// WithDocsRenderer configures the documentation UI renderer (e.g. "stoplight", "scalar", "swagger-ui").
func WithDocsRenderer(renderer string, rendererConfig ...any) Option {
	return func(c *RouterConfig) {
		c.DisableDocs = false
		c.DocsRenderer = renderer
		if len(rendererConfig) > 0 {
			c.DocsRendererConfig = rendererConfig[0]
		}
	}
}

// WithScalarDocs enables the Scalar documentation UI at the specified path (defaults to "/docs").
func WithScalarDocs(docsPath ...string) Option {
	return func(c *RouterConfig) {
		c.DisableDocs = false
		c.DocsRenderer = DocsRendererScalar
		if len(docsPath) > 0 && docsPath[0] != "" {
			c.DocsPath = docsPath[0]
		}
	}
}

// WithSwaggerUIDocs enables the Swagger UI documentation at the specified path (defaults to "/docs").
func WithSwaggerUIDocs(docsPath ...string) Option {
	return func(c *RouterConfig) {
		c.DisableDocs = false
		c.DocsRenderer = DocsRendererSwaggerUI
		if len(docsPath) > 0 && docsPath[0] != "" {
			c.DocsPath = docsPath[0]
		}
	}
}

// WithStoplightDocs enables the Stoplight Elements UI documentation at the specified path (defaults to "/docs").
func WithStoplightDocs(docsPath ...string) Option {
	return func(c *RouterConfig) {
		c.DisableDocs = false
		c.DocsRenderer = DocsRendererStoplight
		if len(docsPath) > 0 && docsPath[0] != "" {
			c.DocsPath = docsPath[0]
		}
	}
}

// WithHumaConfig supplies a base huma.Config to start from.
func WithHumaConfig(cfg huma.Config) Option {
	return func(c *RouterConfig) {
		c.BaseConfig = &cfg
	}
}

// WithConfigure supplies a callback to mutate the huma.Config before API creation.
func WithConfigure(fn func(*huma.Config)) Option {
	return func(c *RouterConfig) {
		c.Configure = fn
	}
}

// BuildConfig resolves the final huma.Config from options.
func BuildConfig(opts ...Option) huma.Config {
	// Step 1: Initialize router configuration with defaults
	rc := DefaultRouterConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&rc)
		}
	}

	// Step 2: Initialize base huma.Config (from BaseConfig or huma.DefaultConfig)
	var cfg huma.Config
	if rc.BaseConfig != nil {
		cfg = *rc.BaseConfig
	} else {
		cfg = huma.DefaultConfig(rc.Title, rc.Version)
	}

	// Step 3: Override title and version if explicitly specified
	if rc.Title != "" {
		if cfg.OpenAPI == nil {
			cfg.OpenAPI = &huma.OpenAPI{}
		}
		if cfg.OpenAPI.Info == nil {
			cfg.OpenAPI.Info = &huma.Info{}
		}
		cfg.OpenAPI.Info.Title = rc.Title
	}
	if rc.Version != "" && cfg.OpenAPI != nil && cfg.OpenAPI.Info != nil {
		cfg.OpenAPI.Info.Version = rc.Version
	}

	// Step 4: Configure OpenAPI and schemas paths
	if rc.OpenAPIPath != "" {
		cfg.OpenAPIPath = rc.OpenAPIPath
	}
	if rc.SchemasPath != "" {
		cfg.SchemasPath = rc.SchemasPath
	}

	// Step 5: Configure documentation path and renderer
	if rc.DisableDocs || (rc.EnableDocs != nil && !*rc.EnableDocs) {
		cfg.DocsPath = ""
	} else {
		if rc.DocsPath != "" {
			cfg.DocsPath = rc.DocsPath
		}
		if rc.DocsRenderer != "" {
			cfg.DocsRenderer = rc.DocsRenderer
		}
		if rc.DocsRendererConfig != nil {
			cfg.DocsRendererConfig = rc.DocsRendererConfig
		}
	}

	// Step 6: Execute caller's custom configuration modifier if present
	if rc.Configure != nil {
		rc.Configure(&cfg)
	}

	return cfg
}

