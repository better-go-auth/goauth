package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bettergoauth "github.com/better-go-auth/goauth"
	coreauth "github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/app/core/profile"
	"github.com/better-go-auth/goauth/src/app/core/session"
	loc_conf "github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	adminsvc "github.com/better-go-auth/goauth/src/plugins/admin/services"
	"github.com/better-go-auth/goauth/src/plugins/org"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/better-go-auth/goauth/src/common/consts"
	redis_storage "github.com/better-go-auth/goauth/src/providers/sec-storage/redis"
	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	test_redis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	TestAccessSecret  = "test-access-secret-key-1234567890"
	TestRefreshSecret = "test-refresh-secret-key-1234567890"
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
	AuthHandler    *coreauth.GinAuthHandler
	ProfileHandler *profile.HProfileHandler
	SessionHandler *session.HumaSessionHandler
	AdminHandler   *humaadmin.AdminHandler
	OrgHandler     *humaorg.OrgHandler

	// Direct services for testing/debugging
	AuthService    *coreauth.Service
	ProfileService *profile.Service
	SessionService *session.Service
	AdminService   adminsvc.IAdminService
	OrgService     orgsvc.IOrgService
}

var containersToCleanup []testcontainers.Container

func SetupTestEnv(t *testing.T, useContainers bool) *TestEnv {
	ctx := context.Background()
	var gormDB *gorm.DB
	var secStorage sec_storage.SecondaryStorage
	teardown := func() {}

	if useContainers {
		slog.Info("========== Using testcontainers")
		pgContainer, err := postgres.Run(ctx,
			"postgres:15-alpine",
			postgres.WithDatabase("testdb"),
			postgres.WithUsername("testuser"),
			postgres.WithPassword("testpass"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(30*time.Second)),
		)
		if err != nil {
			log.Fatalf("failed to start postgres container: %v", err)
		}

		connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			log.Fatalf("failed to get connection string: %v", err)
		}
		gormDB, err = gorm.Open(gormpostgres.Open(connStr), &gorm.Config{
			Logger: logger.Discard,
		})
		if err != nil {
			log.Fatalf("failed to connect to postgres db: %v", err)
		}
		containersToCleanup = append(containersToCleanup, pgContainer)

		//=============================   SECONDARY STORAGE SETUP ==========================|
		//
		//==================================================================================|

		redisContainer, err := test_redis.Run(ctx,
			"redis:7-alpine",
			testcontainers.WithWaitStrategy(
				wait.ForListeningPort("6379/tcp"),
			),
		)
		if err != nil {
			log.Fatalf("failed to start redis container: %v", err)
		}
		containersToCleanup = append(containersToCleanup, redisContainer)

		redisHost, err := redisContainer.Host(ctx)
		if err != nil {
			log.Fatalf("failed to get redis host: %v", err)
		}
		redisPort, err := redisContainer.MappedPort(ctx, "6379")
		if err != nil {
			log.Fatalf("failed to get redis mapped port: %v", err)
		}

		// Establish Redis Connection to Redis Container
		redisClient, err := redis_storage.NewRedisStorage(&redis_storage.Config{
			Host: redisHost,
			Port: redisPort.Port(),
		})
		if err != nil {
			panic("testcommon.Setup: failed to connect to redis test container: " + err.Error())
		}
		secStorage = redisClient

		teardown = func() {
			_ = pgContainer.Terminate(context.Background())
			_ = redisContainer.Terminate(context.Background())
		}
	} else {
		slog.Info("========== Not using testcontainers")
		dbName := fmt.Sprintf("file:memdb_%s?mode=memory&cache=shared", uuid.New().String())
		var err error
		gormDB, err = gorm.Open(sqlite.Open(dbName), &gorm.Config{
			Logger: logger.Discard,
		})
		if err != nil {
			log.Fatalf("failed to connect to sqlite db: %v", err)
		}
		//===========   Setup secondary Storage =========================
		secStorage, err = memory.NewSecondaryStorage()
		if err != nil {
			log.Fatalf("failed to create in-memory secondary storage: %v", err)
		}
	}
	jwt := loc_conf.JwtVar{
		AccessSecret:     TestAccessSecret,
		RefreshSecret:    TestRefreshSecret,
		AccessExpireMin:  60,
		RefreshExpireMin: 1440,
	}

	mockEmail := NewMockEmailSender()

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Better Go Auth Test API", "1.0.0"))

	adminPlugin := admin.NewWithGorm(gormDB, admin.WithSessionConfig(loc_conf.SessionConfig{JwtVar: jwt}))
	orgPlugin := org.NewWithGorm(gormDB, orgconfig.OrgConfig{})

	auth, err := bettergoauth.SetupGoAuth(api, bettergoauth.GoAuthOptions{
		Conn:             gormDB,
		SecondaryStorage: secStorage,
		AuthConfig: loc_conf.AuthConfig{
			EmailVerification: loc_conf.EmailVerification{
				ExpiresIn:              15 * time.Minute,
				VerificationCodeSender: mockEmail,
			},
			SessionConfig: loc_conf.SessionConfig{
				JwtVar: jwt,
			},
		},
		Plugins: []plugin.Plugin{
			adminPlugin,
			orgPlugin,
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
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

	sConf := loc_conf.SessionConfig{JwtVar: jwt}

	// gormauth.NewAuthRepos(opts.Conn)
	authSvc := coreauth.NewAuthService(&sConf, auth.Provider, auth.IAuthServices, auth.IAuthServices, auth.Repositories)
	profileServ := profile.NewProfileServH(auth.Provider, auth.IAuthServices, auth.IAuthServices, auth.Repositories)
	// Handlers
	sSvc := session.NewServiceWithRepo(sConf, auth.Repositories, secStorage)
	authHandler := coreauth.NewAuthHandler(auth.Provider, authSvc)
	profileHandler := profile.NewProfileHandler(auth.Provider, profileServ)
	sessionHandler := session.NewSessionHandler(sSvc)
	adminHandler := adminPlugin.Handler()
	adminService := adminPlugin.Service()
	orgHandler := orgPlugin.Handler()
	orgService := orgPlugin.Service()

	env := &TestEnv{
		Options:          auth.Options,
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
		ProfileHandler: profileHandler,
		SessionHandler: sessionHandler,
		AdminHandler:   adminHandler,
		OrgHandler:     orgHandler,
		// services
		AuthService:    authSvc,
		ProfileService: profileServ,
		SessionService: sSvc,
		AdminService:   adminService,
		OrgService:     orgService,
	}

	if t != nil {
		t.Cleanup(env.Teardown)
	}

	return env
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

func (e *TestEnv) doJSON(method, path string, body any, headers ...map[string]string) (*http.Response, string) {
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

// AuthContext creates a context with user claims for direct handler testing.
func AuthContext(userID, sessionID, role string) context.Context {
	return ContextWithClaims(context.Background(), token.CustomClaims{
		UserID:    userID,
		SessionID: sessionID,
		Role:      role,
	})
}
