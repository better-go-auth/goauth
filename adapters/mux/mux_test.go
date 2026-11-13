package muxadapter_test

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
	muxadapter "github.com/better-go-auth/goauth/adapters/mux"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestMuxAdapter_DocsAndOpenAPI(t *testing.T) {
	t.Run("WithDocs", func(t *testing.T) {
		mux := http.NewServeMux()
		api := muxadapter.New(mux,
			adapters.WithTitle("Mux Test API"),
			adapters.WithDocs("/docs"),
		)
		require.NotNil(t, api)

		server := httptest.NewServer(mux)
		defer server.Close()

		// 1. Check OpenAPI JSON
		res, err := http.Get(server.URL + "/openapi.json")
		require.NoError(t, err)
		defer res.Body.Close()
		require.Equal(t, http.StatusOK, res.StatusCode)
		body, _ := io.ReadAll(res.Body)
		require.Contains(t, string(body), "Mux Test API")

		// 2. Check Docs HTML
		docsRes, err := http.Get(server.URL + "/docs")
		require.NoError(t, err)
		defer docsRes.Body.Close()
		require.Equal(t, http.StatusOK, docsRes.StatusCode)
	})

	t.Run("WithoutDocs", func(t *testing.T) {
		mux := http.NewServeMux()
		api := muxadapter.New(mux, adapters.WithoutDocs())
		require.NotNil(t, api)

		server := httptest.NewServer(mux)
		defer server.Close()

		docsRes, err := http.Get(server.URL + "/docs")
		require.NoError(t, err)
		defer docsRes.Body.Close()
		require.Equal(t, http.StatusNotFound, docsRes.StatusCode)
	})
}

func TestMuxAdapter_SetupGoAuth(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:mux_test_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)

	mux := http.NewServeMux()
	api := muxadapter.New(mux, adapters.WithTitle("Mux Full GoAuth"))

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

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test /ok endpoint
	res, err := http.Get(server.URL + "/api/auth/ok")
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
}

