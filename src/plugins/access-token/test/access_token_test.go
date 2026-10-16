package test

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/better-go-auth/goauth/src/plugins"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"net/http"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type mockEmailSender struct {
	lastCode string
}

func (m *mockEmailSender) SendVerificationCode(to, code string) error {
	m.lastCode = code
	return nil
}

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test sqlite db: %v", err)
	}
	migrator := core_migration.NewGORMAdminMigrator(db)
	if err := migrator.Migrate(context.Background()); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	return db
}

func TestAccessTokenPlugin_FullFlow(t *testing.T) {
	db := setupTestDB(t)
	repos := gormauth.NewAuthRepos(db)
	txMgr := gormutil.NewGormTxManager(db)
	store := sec_storage.New()
	hooks := plugins.NewHookRegistry()
	sessionMgr := sessionsvc.NewManager(config.Session{ExpiresIn: 24 * time.Hour}, repos, repos, store, hooks)

	mockSender := &mockEmailSender{}
	vConf := config.EmailVerification{
		GoAuth: config.EmailVerificationGoAuth{
			CodeExpiresIn: 15 * time.Minute,
			CodeSender:    mockSender,
		},
	}
	sConf := config.SessionGoAuth{
		JWT: config.SessionJWT{
			AccessSecret:     "secret-access-token-key-32-bytes!",
			RefreshSecret:    "secret-refresh-token-key-32-byte!",
			AccessExpiresIn:  15 * time.Minute,
			RefreshExpiresIn: 24 * time.Hour,
		},
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Access Token Test API", "1.0.0"))

	plugin := accesstoken.New(accesstokenconfig.AccessTokenConfig{
		Session:      sConf,
		Verification: vConf,
	})

	authCfg := config.AuthConfig{
		Secret:            "test-app-secret-32-bytes-long!",
		Session:           config.Session{ExpiresIn: 24 * time.Hour},
		EmailVerification: vConf,
		GoAuth: config.GoAuthConfig{
			Session: sConf,
		},
	}
	authCfg.SetDefaults()

	authService := authsvc.New(authsvc.Deps{
		Config:   authCfg,
		Repos:    repos,
		Sessions: sessionMgr,
		Tx:       txMgr,
		Hooks:    hooks,
	})

	initCtx := &plugins.InitContext{
		Ctx:              context.Background(),
		Api:              api,
		IAuthRepos:       repos,
		TxManager:        txMgr,
		SessionManager:   sessionMgr,
		Hooks:            hooks,
		IAuthSvc:         authService,
		Config:           authCfg,
		DB:               db,
		SecondaryStorage: store,
	}

	if err := plugin.Init(initCtx); err != nil {
		t.Fatalf("plugin.Init failed: %v", err)
	}

	if plugin.ID() != "access-token" {
		t.Fatalf("expected plugin ID 'access-token', got '%s'", plugin.ID())
	}

	ctx := context.Background()

	// 1. Register with email
	regResp, err := plugin.AuthService().RegisterWithEmail(ctx, models.RegisterClientInput{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Password:  "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("RegisterWithEmail failed: %v", err)
	}
	if regResp.User.Email != "john.doe@example.com" {
		t.Fatalf("unexpected user email: %s", regResp.User.Email)
	}
	if mockSender.lastCode == "" {
		t.Fatalf("expected verification code to be sent")
	}

	// 2. Verify account
	_, err = repos.UpdateUser(ctx, regResp.User.ID, map[string]interface{}{
		"EmailVerified": true,
		"Active":        true,
	})
	if err != nil {
		t.Fatalf("failed to update user email verified: %v", err)
	}

	// 3. Login
	loginResp, err := plugin.AuthService().Login(ctx, accesstokendtos.LoginData{
		LoginInfo: "john.doe@example.com",
		Password:  "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if loginResp.Body.AuthTokens == nil || loginResp.Body.AuthTokens.AccessToken == "" {
		t.Fatalf("expected non-empty access token")
	}
	refreshToken := loginResp.Body.AuthTokens.RefreshToken
	if refreshToken == "" {
		t.Fatalf("expected non-empty refresh token")
	}

	// 4. Get Profile (commented out as legacy profile service is deprecated)
	// profile, err := plugin.ProfileService().GetProfile(ctx, loginResp.Body.UserData.ID)
	// if err != nil || profile == nil {
	// 	t.Fatalf("GetProfile failed: %v", err)
	// }
	// if profile.Email != "john.doe@example.com" {
	// 	t.Fatalf("unexpected profile email: %s", profile.Email)
	// }

	// 5. Refresh token
	refreshResp, err := plugin.AuthService().ResetToken(ctx, refreshToken)
	if err != nil {
		t.Fatalf("ResetToken failed: %v", err)
	}
	if refreshResp.Body.AuthTokens == nil || refreshResp.Body.AuthTokens.AccessToken == "" {
		t.Fatalf("expected non-empty refreshed access token")
	}

	// 6. Logout
	logoutResp, err := plugin.AuthService().Logout(ctx, refreshResp.Body.AuthTokens.RefreshToken)
	if err != nil || !logoutResp.Body {
		t.Fatalf("Logout failed: %v", err)
	}

	// 7. Verify session deleted
	_, err = plugin.AuthService().ResetToken(ctx, refreshResp.Body.AuthTokens.RefreshToken)
	if err == nil {
		t.Fatalf("expected ResetToken to fail after logout")
	}
}
