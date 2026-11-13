package chiadapter_test

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
	chiadapter "github.com/better-go-auth/goauth/adapters/chi"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestChiAdapter_DocsAndOpenAPI(t *testing.T) {
	r := chi.NewRouter()
	api := chiadapter.New(r,
		adapters.WithTitle("Chi Auth API"),
		adapters.WithVersion("1.1.0"),
		adapters.WithScalarDocs("/scalar-docs"),
	)
	require.NotNil(t, api)

	server := httptest.NewServer(r)
	defer server.Close()

	// 1. Verify OpenAPI
	res, err := http.Get(server.URL + "/openapi.json")
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	body, _ := io.ReadAll(res.Body)
	require.Contains(t, string(body), "Chi Auth API")

	// 2. Verify Scalar Docs
	docsRes, err := http.Get(server.URL + "/scalar-docs")
	require.NoError(t, err)
	defer docsRes.Body.Close()
	require.Equal(t, http.StatusOK, docsRes.StatusCode)
}

func TestChiAdapter_SetupGoAuth(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:chi_test_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)

	r := chi.NewRouter()
	api := chiadapter.New(r, adapters.WithTitle("Chi Full GoAuth"))

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

	server := httptest.NewServer(r)
	defer server.Close()

	// Test /ok endpoint
	res, err := http.Get(server.URL + "/api/auth/ok")
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
}

