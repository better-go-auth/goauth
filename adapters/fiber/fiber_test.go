package fiberadapter_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/adapters"
	fiberadapter "github.com/better-go-auth/goauth/adapters/fiber"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	fiber "github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestFiberAdapter_DocsAndOpenAPI(t *testing.T) {
	app := fiber.New()
	api := fiberadapter.New(app,
		adapters.WithTitle("Fiber Auth API"),
		adapters.WithDocs("/fiber-docs"),
	)
	require.NotNil(t, api)

	// 1. Verify OpenAPI via Fiber Test
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(body), "Fiber Auth API")

	// 2. Verify Docs via Fiber Test
	docsReq := httptest.NewRequest(http.MethodGet, "/fiber-docs", nil)
	docsResp, err := app.Test(docsReq)
	require.NoError(t, err)
	defer docsResp.Body.Close()
	require.Equal(t, http.StatusOK, docsResp.StatusCode)
}

func TestFiberAdapter_SetupGoAuth(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:fiber_test_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)

	app := fiber.New()
	api := fiberadapter.New(app, adapters.WithTitle("Fiber Full GoAuth"))

	_, err = goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		AuthConfig: config.AuthConfig{
			AppName:  "Router Adapter Test",
			BaseURL:  "http://localhost:8080",
			Secret:   "adapter-test-secret-32-bytes-long!!",
			BasePath: "/api/auth",
		},
		Conn:    db,
		Plugins: []plugin.Plugin{bearer.New(bearerconfig.DefaultConfig())},
	})
	require.NoError(t, err)

	// Test /ok endpoint via Fiber app.Test
	req := httptest.NewRequest(http.MethodGet, "/api/auth/ok", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

