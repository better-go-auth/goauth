package adapters_test

import (
	"testing"

	"github.com/better-go-auth/goauth/adapters"
	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"
)

func TestBuildConfig_Options(t *testing.T) {
	t.Run("Defaults", func(t *testing.T) {
		cfg := adapters.BuildConfig()
		require.Equal(t, "Better Go Auth API", cfg.OpenAPI.Info.Title)
		require.Equal(t, "1.0.0", cfg.OpenAPI.Info.Version)
		require.Equal(t, "/docs", cfg.DocsPath)
		require.Equal(t, "/openapi", cfg.OpenAPIPath)
		require.Equal(t, "/schemas", cfg.SchemasPath)
		require.Equal(t, adapters.DocsRendererStoplight, cfg.DocsRenderer)
	})

	t.Run("CustomTitleAndVersion", func(t *testing.T) {
		cfg := adapters.BuildConfig(
			adapters.WithTitle("Custom Title"),
			adapters.WithVersion("2.5.0"),
		)
		require.Equal(t, "Custom Title", cfg.OpenAPI.Info.Title)
		require.Equal(t, "2.5.0", cfg.OpenAPI.Info.Version)
	})

	t.Run("WithoutDocs", func(t *testing.T) {
		cfg := adapters.BuildConfig(adapters.WithoutDocs())
		require.Empty(t, cfg.DocsPath)
	})

	t.Run("WithEnableDocs", func(t *testing.T) {
		// 1. Explicitly enabled with default path
		cfgTrue := adapters.BuildConfig(adapters.WithEnableDocs(true))
		require.Equal(t, "/docs", cfgTrue.DocsPath)

		// 2. Explicitly enabled with custom path
		cfgCustom := adapters.BuildConfig(adapters.WithEnableDocs(true, "/custom-docs"))
		require.Equal(t, "/custom-docs", cfgCustom.DocsPath)

		// 3. Explicitly disabled
		cfgFalse := adapters.BuildConfig(adapters.WithEnableDocs(false))
		require.Empty(t, cfgFalse.DocsPath)

		// 4. WithDocs() with no arguments defaults to /docs
		cfgWithDocsDefault := adapters.BuildConfig(adapters.WithDocs())
		require.Equal(t, "/docs", cfgWithDocsDefault.DocsPath)
	})

	t.Run("CustomDocsAndRenderers", func(t *testing.T) {
		scalarCfg := adapters.BuildConfig(adapters.WithScalarDocs("/api/documentation"))
		require.Equal(t, "/api/documentation", scalarCfg.DocsPath)
		require.Equal(t, adapters.DocsRendererScalar, scalarCfg.DocsRenderer)

		swaggerCfg := adapters.BuildConfig(adapters.WithSwaggerUIDocs("/swagger"))
		require.Equal(t, "/swagger", swaggerCfg.DocsPath)
		require.Equal(t, adapters.DocsRendererSwaggerUI, swaggerCfg.DocsRenderer)

		stoplightCfg := adapters.BuildConfig(adapters.WithStoplightDocs("/elements"))
		require.Equal(t, "/elements", stoplightCfg.DocsPath)
		require.Equal(t, adapters.DocsRendererStoplight, stoplightCfg.DocsRenderer)
	})

	t.Run("WithConfigure", func(t *testing.T) {
		cfg := adapters.BuildConfig(adapters.WithConfigure(func(c *huma.Config) {
			c.OpenAPI.Info.Description = "Custom description set by callback"
		}))
		require.Equal(t, "Custom description set by callback", cfg.OpenAPI.Info.Description)
	})
}

