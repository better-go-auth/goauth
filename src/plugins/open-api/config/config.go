// Package config holds the options of the open-api plugin (better-auth's OpenAPIOptions).
package config

import "github.com/better-go-auth/goauth/src/schema"

// DefaultPath is the default path of the reference page, relative to BasePath ("/api/auth/reference").
const DefaultPath = "/reference"

// DefaultTheme is the Scalar theme better-auth uses when none is set.
const DefaultTheme = "default"

// OpenAPIConfig holds the options of the open-api plugin.
type OpenAPIConfig struct {
	// Path is the path of the Scalar reference page relative to BasePath (default "/reference").
	Path string
	// DisableDefaultReference turns the reference page off: it answers 404 NOT_FOUND
	// (GET /open-api/generate-schema keeps working).
	DisableDefaultReference bool
	// Theme is the Scalar theme (default "default"; e.g. "alternate", "moon", "purple", "solarized",
	// "bluePlanet", "saturn", "kepler", "mars", "deepSpace", "laserwave", "none").
	Theme string
	// Nonce is added as a nonce attribute to the page's scripts (Content-Security-Policy).
	Nonce string
	// Schemas are plugin schemas added to components.schemas, like better-auth's getAuthTables does with
	// the installed plugins' `schema` (e.g. the models of a plugin implementing plugins.SchemaProvider).
	// The user/session fields of goauth's built-in plugins are included automatically when installed.
	Schemas []schema.Plugin
}

// WithDefaults fills the unset options.
func (c OpenAPIConfig) WithDefaults() OpenAPIConfig {
	if c.Path == "" {
		c.Path = DefaultPath
	}
	if c.Theme == "" {
		c.Theme = DefaultTheme
	}
	return c
}
