package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bettergoauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/common/consts"
	loc_conf "github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	humaaccesstoken "github.com/better-go-auth/goauth/src/plugins/access-token/adapters/huma"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	accesstokensvc "github.com/better-go-auth/goauth/src/plugins/access-token/services"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	adminsvc "github.com/better-go-auth/goauth/src/plugins/admin/services"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	redis_storage "github.com/better-go-auth/goauth/src/providers/sec-storage/redis"
	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/testcontainers/testcontainers-go"
	test_redis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/gorm"
)

const (
	TestAccessSecret = "test-access-secret-key-1234567890"
)

type TestEnv struct {
	Options          bettergoauth.GoAuthOptions
	DB               *gorm.DB
	SecondaryStorage sec_storage.SecondaryStorage
	Auth             *bettergoauth.GoAuth
	HumaAPI          huma.API
	Mux              *http.ServeMux
	MockEmail        *MockEmailSender
	Server           *httptest.Server
	BaseURL          string
	Teardown         func()

	// Direct handlers for in-process debugging
	AuthHandler    *humaaccesstoken.AccessTokenHandler
	ProfileHandler *humaaccesstoken.AccessTokenHandler
	SessionHandler *humaaccesstoken.AccessTokenHandler
	AdminHandler   *humaadmin.AdminHandler
	OrgHandler     *humaorg.OrgHandler

	// Direct services for testing/debugging
	AuthService *accesstokensvc.AuthService
	// ProfileService *accesstokensvc.ProfileService
	SessionService *accesstokensvc.SessionService
	AdminService   adminsvc.IAdminService
	OrgService     orgsvc.IOrgService
}

var containersToCleanup []testcontainers.Container

// SetupTestEnv initializes a TestEnv using either PostgreSQL container (useContainers=true) or SQLite (useContainers=false).
func SetupTestEnv(t *testing.T, useContainers bool) *TestEnv {
	if useContainers {
		return SetupTestEnvWithDB(t, DBTypePostgres)
	}
	return SetupTestEnvWithDB(t, DBTypeSQLite)
}

// SetupTestEnvWithDB initializes a TestEnv using the specified database engine (SQLite, PostgreSQL, or MySQL).
func SetupTestEnvWithDB(t *testing.T, dbType DatabaseType) *TestEnv {
	t.Helper()
	gormDB := SetupTestDB(t, dbType)
	if gormDB == nil {
		return nil
	}

	var secStorage sec_storage.SecondaryStorage
	teardown := func() {}

	// Step 1: For container-based DBs, pair with Redis if available
	if dbType != DBTypeSQLite {
		ctx := context.Background()
		redisContainer, err := test_redis.Run(
			ctx,
			"redis:7-alpine",
			testcontainers.WithWaitStrategy(
				wait.ForListeningPort("6379/tcp"),
			),
		)
		if err == nil {
			redisHost, err := redisContainer.Host(ctx)
			if err == nil {
				redisPort, err := redisContainer.MappedPort(ctx, "6379")
				if err == nil {
					redisClient, err := redis_storage.NewRedisStorage(&redis_storage.Config{
						Host: redisHost,
						Port: redisPort.Port(),
					})
					if err == nil {
						secStorage = redisClient
						teardown = func() {
							_ = redisContainer.Terminate(context.Background())
						}
					}
				}
			}
		}
	}

	// Step 2: Fall back to memory secondary storage if Redis is not used or unavailable
	if secStorage == nil {
		var err error
		secStorage, err = memory.NewSecondaryStorage()
		if err != nil {
			t.Fatalf("failed to create in-memory secondary storage: %v", err)
		}
	}
	jwt := accesstokenconfig.SessionJWT{
		AccessSecret:    TestAccessSecret,
		AccessExpiresIn: time.Hour,
	}

	mockEmail := NewMockEmailSender()

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Better Go Auth Test API", "1.0.0"))

	adminPlugin, err := admin.NewWithGorm(gormDB)
	if err != nil {
		t.Fatalf("failed to initialize admin plugin: %v", err)
	}

	orgPlugin, err := org.NewWithGorm(gormDB, orgconfig.OrgConfig{})
	if err != nil {
		t.Fatalf("failed to initialize org plugin: %v", err)
	}

	accessTokenPlugin := accesstoken.New(accesstokenconfig.AccessTokenConfig{
		Session:                accesstokenconfig.SessionGoAuth{JWT: jwt},
		AutoRegisterMiddleware: true,
	})

	auth, err := bettergoauth.SetupGoAuth(context.Background(), api, bettergoauth.GoAuthOptions{
		Conn:             gormDB,
		SecondaryStorage: secStorage,
		AuthConfig: loc_conf.AuthConfig{
			BaseURL: "http://127.0.0.1:3000",
			Secret:  TestAccessSecret,
			EmailVerification: loc_conf.EmailVerification{
				GoAuth: loc_conf.EmailVerificationGoAuth{
					CodeExpiresIn: 15 * time.Minute,
					CodeSender:    mockEmail,
				},
			},
			TrustedOrigins: []string{"http://127.0.0.1:*", "http://localhost:*"},
		},
		Plugins: []plugin.Plugin{
			bearer.New(bearerconfig.DefaultConfig()),
			adminPlugin,
			orgPlugin,
			accessTokenPlugin,
		},
	})
	if err != nil {
		t.Fatalf("failed to initialize auth: %v", err)
	}

	// Test helper endpoint to inspect tokens
	type LastTokenInput struct {
		Email string `query:"email" required:"true"`
	}
	type LastTokenOutput struct {
		Body struct {
			Email string `json:"email"`
			Token string `json:"token"`
		}
	}
	huma.Register(api, huma.Operation{
		Method: http.MethodGet,
		Path:   "/api/auth/test/last-token",
	}, func(ctx context.Context, input *LastTokenInput) (*LastTokenOutput, error) {
		token, ok := mockEmail.LastToken(input.Email)
		if !ok {
			return nil, huma.Error404NotFound("token not found")
		}
		out := &LastTokenOutput{}
		out.Body.Email = input.Email
		out.Body.Token = token
		return out, nil
	})

	server := httptest.NewServer(mux)
	prevTeardown := teardown
	fullTeardown := func() {
		server.Close()
		prevTeardown()
	}

	authHandler := accessTokenPlugin.Handler()
	authSvc := accessTokenPlugin.AuthService()
	// profileServ := accessTokenPlugin.ProfileService()
	sSvc := accessTokenPlugin.SessionService()
	adminHandler := adminPlugin.Handler()
	adminService := adminPlugin.Service()
	orgHandler := orgPlugin.Handler()
	orgService := orgPlugin.Service()

	env := &TestEnv{
		Options:          auth.Options(),
		DB:               gormDB,
		SecondaryStorage: secStorage,
		Auth:             auth,
		HumaAPI:          api,
		Mux:              mux,
		MockEmail:        mockEmail,
		Server:           server,
		BaseURL:          server.URL,
		Teardown:         fullTeardown,
		// handler
		AuthHandler:    authHandler,
		ProfileHandler: authHandler,
		SessionHandler: authHandler,
		AdminHandler:   adminHandler,
		OrgHandler:     orgHandler,
		// services
		AuthService: authSvc,
		// ProfileService: profileServ,
		SessionService: sSvc,
		AdminService:   adminService,
		OrgService:     orgService,
	}

	if t != nil {
		t.Cleanup(env.Teardown)
	}

	return env
}

// RunForEachDBEnv executes a test suite against all supported database environments (SQLite, PostgreSQL, MySQL).
func RunForEachDBEnv(t *testing.T, fn func(t *testing.T, env *TestEnv, dbType DatabaseType)) {
	t.Helper()

	for _, dbType := range AllDatabaseTypes {
		t.Run(string(dbType), func(t *testing.T) {
			env := SetupTestEnvWithDB(t, dbType)
			if env == nil {
				return
			}
			fn(t, env, dbType)
		})
	}
}

// Request helpers

func (e *TestEnv) PostJSON(path string, body any, headers ...map[string]string) (*http.Response, string) {
	return e.doJSON(http.MethodPost, path, body, headers...)
}

func (e *TestEnv) GetJSON(path string, headers ...map[string]string) (*http.Response, string) {
	return e.doJSON(http.MethodGet, path, nil, headers...)
}

func (e *TestEnv) PatchJSON(path string, body any, headers ...map[string]string) (*http.Response, string) {
	return e.doJSON(http.MethodPatch, path, body, headers...)
}

func (e *TestEnv) DeleteJSON(path string, body any, headers ...map[string]string) (*http.Response, string) {
	return e.doJSON(http.MethodDelete, path, body, headers...)
}

// doJSONWithT is the test-aware variant that uses t.Helper and t.Fatalf instead of panicking.
func (e *TestEnv) doJSONWithT(t interface {
	Helper()
	Fatalf(string, ...any)
}, method, path string, body any, headers ...map[string]string) (*http.Response, string) {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("doJSON: marshal error: %v", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequest(method, e.BaseURL+path, bodyReader)
	if err != nil {
		t.Fatalf("doJSON: request creation error: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, h := range headers {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("doJSON: client execution error: %v", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("doJSON: read body error: %v", err)
	}
	return resp, string(respBytes)
}

func (e *TestEnv) doJSON(method, path string, body any, headers ...map[string]string) (*http.Response, string) {
	// caller is TestEnv helper; mark as helper if *testing.T is available via not panicking path
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			panic(fmt.Sprintf("doJSON: marshal error: %v", err))
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, e.BaseURL+path, bodyReader)
	if err != nil {
		panic(fmt.Sprintf("doJSON: request creation error: %v", err))
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for _, h := range headers {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(fmt.Sprintf("doJSON: client execution error: %v", err))
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("doJSON: read body error: %v", err))
	}

	return resp, string(respBytes)
}

// ContextWithClaims wraps a context with authenticated token.CustomClaims for direct handler testing.
func ContextWithClaims(ctx context.Context, claims token.CustomClaims) context.Context {
	return context.WithValue(ctx, consts.CtxClaims.Str(), claims)
}

// SignedBearerAuth signs a raw opaque session token with HMAC-SHA256 for Authorization: Bearer requests.
func SignedBearerAuth(rawToken, secret string) string {
	return "Bearer " + cookies.SignCookieValue(rawToken, secret)
}

// SignedBearerHeader signs an existing `Bearer <rawToken>` header map for HTTP requests.
func SignedBearerHeader(hdr map[string]string, secret string) map[string]string {
	out := make(map[string]string, len(hdr))
	for k, v := range hdr {
		out[k] = v
	}
	if auth, ok := out["Authorization"]; ok && len(auth) > 7 && auth[:7] == "Bearer " {
		out["Authorization"] = SignedBearerAuth(auth[7:], secret)
	}
	return out
}

// AuthContext creates a context with user claims for direct handler testing.
func AuthContext(userID, sessionID, role string) context.Context {
	return ContextWithClaims(context.Background(), token.CustomClaims{
		UserID:    userID,
		SessionID: sessionID,
		Role:      role,
	})
}
