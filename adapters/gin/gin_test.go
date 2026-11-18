package ginadapter_test

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
	ginadapter "github.com/better-go-auth/goauth/adapters/gin"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestGinAdapter_DocsAndOpenAPI(t *testing.T) {
	r := gin.New()
	api := ginadapter.New(r,
		adapters.WithTitle("Gin Auth API"),
		adapters.WithSwaggerUIDocs("/swagger-ui"),
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
	require.Contains(t, string(body), "Gin Auth API")

	// 2. Verify Swagger UI Docs
	docsRes, err := http.Get(server.URL + "/swagger-ui")
	require.NoError(t, err)
	defer docsRes.Body.Close()
	require.Equal(t, http.StatusOK, docsRes.StatusCode)
}

func TestGinAdapter_SetupGoAuth(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:gin_test_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)

	r := gin.New()
	api := ginadapter.New(r, adapters.WithTitle("Gin Full GoAuth"))

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
