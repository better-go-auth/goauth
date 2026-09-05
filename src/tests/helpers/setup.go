package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	bettergoauth "github.com/better-go-auth/goauth"
	loc_conf "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	"github.com/birukbelay/gocmn/src/config"
	"github.com/birukbelay/gocmn/src/provider/db"
	gocmn_redis "github.com/birukbelay/gocmn/src/provider/db/redis"
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
	DB               *gorm.DB
	SecondaryStorage db.KeyValServ
	Auth             *bettergoauth.GoAuth
	HumaAPI          huma.API
	Mux              *http.ServeMux
	MockEmail        *MockEmailSender
	Server           *httptest.Server
	BaseURL          string
	Teardown         func()
}

var containersToCleanup []testcontainers.Container

func SetupTestEnv(t *testing.T) *TestEnv {
	ctx := context.Background()
	var gormDB *gorm.DB
	var redisClient *gocmn_redis.RedisService
	var teardown = func() {}

	if os.Getenv("USE_TESTCONTAINERS") == "true" {
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
		containersToCleanup = append(containersToCleanup, pgContainer)

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

		_ = redisHost
		_ = redisPort

		gormDB, err = gorm.Open(gormpostgres.Open(connStr), &gorm.Config{
			Logger: logger.Discard,
		})
		if err != nil {
			log.Fatalf("failed to connect to postgres db: %v", err)
		}

		teardown = func() {
			_ = pgContainer.Terminate(context.Background())
			_ = redisContainer.Terminate(context.Background())
		}
	} else {
		dbName := fmt.Sprintf("file:memdb_%s?mode=memory&cache=shared", uuid.New().String())
		var err error
		gormDB, err = gorm.Open(sqlite.Open(dbName), &gorm.Config{
			Logger: logger.Discard,
		})
		if err != nil {
			log.Fatalf("failed to connect to sqlite db: %v", err)
		}
	}

	// Migrate core models
	if err := gormDB.AutoMigrate(
		&models.User{},
		&models.Account{},
		&models.Session{},
		&models.Verification{},
	); err != nil {
		log.Fatalf("failed to auto migrate models: %v", err)
	}

	mockEmail := NewMockEmailSender()

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Better Go Auth Test API", "1.0.0"))

	adminPlugin := admin.NewWithGorm(gormDB, admin.WithJwtSecret(TestAccessSecret))

	auth, err := bettergoauth.SetupGoAuth(api, loc_conf.GoAuthOptions{
		Conn: gormDB,
		EmailVerification: loc_conf.EmailVerification{
			ExpiresIn:              15 * time.Minute,
			VerificationCodeSender: mockEmail,
		},
		SessionConfig: loc_conf.SessionConfig{
			JwtVar: config.JwtVar{
				AccessSecret:     TestAccessSecret,
				RefreshSecret:    TestRefreshSecret,
				AccessExpireMin:  60,
				RefreshExpireMin: 1440,
			},
		},
		Plugins: []plugin.Plugin{
			adminPlugin,
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

	env := &TestEnv{
		DB:               gormDB,
		SecondaryStorage: redisClient,
		Auth:             auth,
		HumaAPI:          api,
		Mux:              mux,
		MockEmail:        mockEmail,
		Server:           server,
		BaseURL:          server.URL,
		Teardown:         fullTeardown,
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
