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
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/better-go-auth/goauth/src/plugins"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"net/http"
	"net/http/httptest"
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
	sConf := accesstokenconfig.SessionGoAuth{
		JWT: accesstokenconfig.SessionJWT{
			AccessSecret:    "secret-access-token-key-32-bytes!",
			AccessExpiresIn: 15 * time.Minute,
		},
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Access Token Test API", "1.0.0"))

	plugin := accesstoken.New(accesstokenconfig.AccessTokenConfig{
		Session: sConf,
	})

	authCfg := config.AuthConfig{
		Secret:            "test-app-secret-32-bytes-long!",
		Session:           config.Session{ExpiresIn: 24 * time.Hour},
		EmailVerification: vConf,
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
	regResp, err := plugin.AuthService().RegisterWithEmail(ctx, accesstokendtos.RegisterClientInput{
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

func TestAccessTokenConfigDefaults(t *testing.T) {
	cfg := accesstokenconfig.DefaultAccessTokenConfig()
	if cfg.Session.JWT.AccessExpiresIn != 15*time.Minute {
		t.Errorf("expected AccessExpiresIn 15m, got %v", cfg.Session.JWT.AccessExpiresIn)
	}
	if len(cfg.Session.UpdatableFields) == 0 {
		t.Errorf("expected default updatable fields to be set")
	}
	if cfg.AutoRegisterMiddleware {
		t.Errorf("expected AutoRegisterMiddleware to be false by default")
	}
}

func TestRefreshToken_RejectsAccessTokenJWT(t *testing.T) {
	db := setupTestDB(t)
	repos := gormauth.NewAuthRepos(db)
	txMgr := gormutil.NewGormTxManager(db)
	store := sec_storage.New()
	hooks := plugins.NewHookRegistry()
	sessionMgr := sessionsvc.NewManager(config.Session{ExpiresIn: 24 * time.Hour}, repos, repos, store, hooks)

	sConf := accesstokenconfig.SessionGoAuth{
		JWT: accesstokenconfig.SessionJWT{
			AccessSecret:    "jwt-access-secret-32-chars-long!",
			AccessExpiresIn: 15 * time.Minute,
		},
	}

	authCfg := config.AuthConfig{
		Secret:  "core-app-secret-32-chars-long!!",
		Session: config.Session{ExpiresIn: 24 * time.Hour},
		EmailVerification: config.EmailVerification{
			GoAuth: config.EmailVerificationGoAuth{
				CodeExpiresIn: 15 * time.Minute,
				CodeSender:    &mockEmailSender{},
			},
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

	plugin := accesstoken.New(accesstokenconfig.AccessTokenConfig{
		Session: sConf,
	})

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Access Token Test API", "1.0.0"))

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

	ctx := context.Background()

	// 1. Create a user and log in to get access token JWT and session refresh token
	regResp, err := plugin.AuthService().RegisterWithEmail(ctx, accesstokendtos.RegisterClientInput{
		FirstName: "Token",
		LastName:  "Test",
		Email:     "tokentest@example.com",
		Password:  "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("RegisterWithEmail failed: %v", err)
	}
	_, _ = repos.UpdateUser(ctx, regResp.User.ID, map[string]interface{}{"EmailVerified": true})

	loginResp, err := plugin.AuthService().Login(ctx, accesstokendtos.LoginData{
		LoginInfo: "tokentest@example.com",
		Password:  "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	accessJWT := loginResp.Body.AuthTokens.AccessToken
	refreshToken := loginResp.Body.AuthTokens.RefreshToken

	// 2. Passing the access token JWT to ResetToken MUST be rejected as an invalid token!
	_, err = plugin.AuthService().ResetToken(ctx, accessJWT)
	if err == nil {
		t.Fatalf("expected ResetToken to reject 3-segment access token JWT, but it succeeded")
	}

	// 3. Passing the access token JWT to FindByRefreshToken MUST be rejected!
	_, err = plugin.SessionService().FindByRefreshToken(ctx, accessJWT)
	if err == nil {
		t.Fatalf("expected FindByRefreshToken to reject 3-segment access token JWT, but it succeeded")
	}

	// 4. Passing the access token JWT to Logout MUST be rejected!
	_, err = plugin.AuthService().Logout(ctx, accessJWT)
	if err == nil {
		t.Fatalf("expected Logout to reject 3-segment access token JWT, but it succeeded")
	}

	// 5. Passing the genuine refresh token to ResetToken MUST succeed!
	resetResp, err := plugin.AuthService().ResetToken(ctx, refreshToken)
	if err != nil {
		t.Fatalf("ResetToken failed with valid refresh token: %v", err)
	}
	if resetResp.Body.AuthTokens == nil || resetResp.Body.AuthTokens.AccessToken == "" {
		t.Fatalf("expected new tokens after refresh")
	}
}

func TestSecretSeparation_CookiesUseCoreSecret(t *testing.T) {
	db := setupTestDB(t)
	repos := gormauth.NewAuthRepos(db)
	txMgr := gormutil.NewGormTxManager(db)
	store := sec_storage.New()
	hooks := plugins.NewHookRegistry()
	sessionMgr := sessionsvc.NewManager(config.Session{ExpiresIn: 24 * time.Hour}, repos, repos, store, hooks)

	coreSecret := "core-app-secret-32-chars-long!!"
	accessSecret := "jwt-access-secret-32-chars-diff!"

	sConf := accesstokenconfig.SessionGoAuth{
		JWT: accesstokenconfig.SessionJWT{
			AccessSecret:    accessSecret,
			AccessExpiresIn: 15 * time.Minute,
		},
	}

	authCfg := config.AuthConfig{
		Secret:  coreSecret,
		Session: config.Session{ExpiresIn: 24 * time.Hour},
		EmailVerification: config.EmailVerification{
			GoAuth: config.EmailVerificationGoAuth{
				CodeExpiresIn: 15 * time.Minute,
				CodeSender:    &mockEmailSender{},
			},
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

	plugin := accesstoken.New(accesstokenconfig.AccessTokenConfig{
		Session: sConf,
	})

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Access Token Test API", "1.0.0"))

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

	// Assert that sessionSvc has the core secret, NOT the access secret
	if plugin.SessionService().Secret != coreSecret {
		t.Fatalf("expected session service to use core secret %q, got %q", coreSecret, plugin.SessionService().Secret)
	}

	ctx := context.Background()

	// 1. Register and login
	regResp, err := plugin.AuthService().RegisterWithEmail(ctx, accesstokendtos.RegisterClientInput{
		FirstName: "Cookie",
		LastName:  "Test",
		Email:     "cookietest@example.com",
		Password:  "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("RegisterWithEmail failed: %v", err)
	}
	_, _ = repos.UpdateUser(ctx, regResp.User.ID, map[string]interface{}{"EmailVerified": true})

	loginResp, err := plugin.AuthService().Login(ctx, accesstokendtos.LoginData{
		LoginInfo: "cookietest@example.com",
		Password:  "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	refreshToken := loginResp.Body.AuthTokens.RefreshToken

	// 2. Sign cookie using CORE secret -> FindByRefreshToken must succeed!
	signedWithCoreSecret := cookies.SignCookieValue(refreshToken, coreSecret)
	sess, err := plugin.SessionService().FindByRefreshToken(ctx, signedWithCoreSecret)
	if err != nil || sess == nil {
		t.Fatalf("expected FindByRefreshToken to verify cookie signed with core secret: %v", err)
	}

	// 3. Sign cookie using ACCESS secret -> FindByRefreshToken MUST NOT verify it as a valid core cookie!
	signedWithAccessSecret := cookies.SignCookieValue(refreshToken, accessSecret)
	// Because VerifyCookieValue checks with core secret, it returns false for the accessSecret signature,
	// and strips only if valid. If it treated AccessSecret as cookie secret, it would have verified it.
	// We verify that cookies.VerifyCookieValue with sessionSvc.Secret rejects the access-signed cookie:
	if _, ok := cookies.VerifyCookieValue(signedWithAccessSecret, plugin.SessionService().Secret); ok {
		t.Fatalf("cookie signed with access secret should NOT verify against core secret")
	}
}

func TestScopedProtection_RequireRefreshToken(t *testing.T) {
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Guard Test API", "1.0.0"))

	plugin := accesstoken.New(accesstokenconfig.AccessTokenConfig{})

	type GuardInput struct {
		Authorization string `header:"Authorization"`
	}
	type GuardOutput struct {
		Body struct {
			Success bool `json:"success"`
		}
	}

	huma.Register(api, huma.Operation{
		Method:      http.MethodPost,
		Path:        "/api/custom/refresh-only",
		Middlewares: huma.Middlewares{plugin.RequireRefreshToken()},
	}, func(ctx context.Context, input *GuardInput) (*GuardOutput, error) {
		out := &GuardOutput{}
		out.Body.Success = true
		return out, nil
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// 1. Sending 3-segment JWT access token to refresh-only endpoint must return 401 Unauthorized
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/custom/refresh-only", nil)
	req.Header.Set("Authorization", "Bearer header.payload.signature")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for access JWT on refresh-only endpoint, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Sending opaque session token must pass guard
	req2, _ := http.NewRequest(http.MethodPost, server.URL+"/api/custom/refresh-only", nil)
	req2.Header.Set("Authorization", "Bearer some-opaque-session-token-without-two-dots")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 for opaque refresh token, got %d", resp2.StatusCode)
	}
	_ = resp2.Body.Close()
}
