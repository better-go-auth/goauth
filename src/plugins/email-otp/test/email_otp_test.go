package test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/better-go-auth/goauth/src/plugins"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type mockOTPSender struct {
	lastData emailotpconfig.SendVerificationOTPData
}

func (m *mockOTPSender) Send(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
	m.lastData = data
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

func TestEmailOTPPlugin_LifecycleAndEndpoints(t *testing.T) {
	db := setupTestDB(t)
	repos := gormauth.NewAuthRepos(db)
	txMgr := gormutil.NewGormTxManager(db)
	store := sec_storage.New()
	hooks := plugins.NewHookRegistry()
	sessionMgr := sessionsvc.NewManager(config.Session{ExpiresIn: 24 * time.Hour}, repos, repos, store, hooks)

	sender := &mockOTPSender{}
	otpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
		SendVerificationOTP:      sender.Send,
		OtpLength:                6,
		ExpiresIn:                5 * time.Minute,
		SendVerificationOnSignUp: true,
	})

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Email OTP Test API", "1.0.0"))

	ctx := context.Background()
	authCfg := config.AuthConfig{
		Secret:  "test-secret-at-least-32-chars-long!",
		AppName: "Test App",
		Session: config.Session{ExpiresIn: 24 * time.Hour},
	}
	authCfg.SetDefaults()

	ictx := &plugins.InitContext{
		Ctx:            ctx,
		Api:            api,
		Config:         authCfg,
		TxManager:      txMgr,
		SessionManager: sessionMgr,
		IAuthRepos:     repos,
		Hooks:          hooks,
	}

	if err := otpPlugin.Init(ictx); err != nil {
		t.Fatalf("otpPlugin.Init failed: %v", err)
	}

	svc := otpPlugin.Service()
	testEmail := "test.otp@example.com"

	// 1. Send OTP for email verification
	err := svc.SendVerificationOTP(ctx, testEmail, emailotpconfig.OTPTypeEmailVerification, nil)
	if err != nil {
		t.Fatalf("SendVerificationOTP failed: %v", err)
	}
	if len(sender.lastData.OTP) != 6 {
		t.Fatalf("expected 6-digit OTP, got %s", sender.lastData.OTP)
	}
	if sender.lastData.Type != emailotpconfig.OTPTypeEmailVerification {
		t.Fatalf("expected type email-verification, got %s", sender.lastData.Type)
	}
	code := sender.lastData.OTP

	// 2. Check Verification OTP (pre-validate without consuming)
	if err := svc.CheckVerificationOTP(ctx, testEmail, code, emailotpconfig.OTPTypeEmailVerification); err != nil {
		t.Fatalf("CheckVerificationOTP failed: %v", err)
	}
	if err := svc.CheckVerificationOTP(ctx, testEmail, "000000", emailotpconfig.OTPTypeEmailVerification); err == nil {
		t.Fatalf("expected error for invalid OTP code")
	}

	// 3. Create unverified user in DB
	u, err := repos.CreateUser(ctx, &models.User{
		Base: models.Base{ID: models.NewID()},
		UserDto: models.UserDto{
			Email:         testEmail,
			Name:          "Test OTP User",
			EmailVerified: false,
		},
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// 4. Verify Email with OTP
	_, updatedUser, err := svc.VerifyEmail(ctx, testEmail, code, sessionsvc.Meta{}, nil)
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	if !updatedUser.EmailVerified {
		t.Fatalf("expected EmailVerified to be true")
	}

	// Code was consumed, verifying again should fail
	if err := svc.CheckVerificationOTP(ctx, testEmail, code, emailotpconfig.OTPTypeEmailVerification); err == nil {
		t.Fatalf("expected OTP to be consumed")
	}

	// 5. Passwordless Sign-In with OTP
	signInEmail := "signin.otp@example.com"
	err = svc.SendVerificationOTP(ctx, signInEmail, emailotpconfig.OTPTypeSignIn, nil)
	if err != nil {
		t.Fatalf("SendVerificationOTP for sign-in failed: %v", err)
	}
	signInCode := sender.lastData.OTP

	session, err := svc.SignIn(ctx, signInEmail, signInCode, sessionsvc.Meta{})
	if err != nil {
		t.Fatalf("SignIn with OTP failed: %v", err)
	}
	if session == nil || session.User.Email != signInEmail {
		t.Fatalf("expected active session for %s", signInEmail)
	}

	// 6. Reset Password with OTP
	resetEmail := testEmail
	err = svc.SendVerificationOTP(ctx, resetEmail, emailotpconfig.OTPTypeForgetPassword, nil)
	if err != nil {
		t.Fatalf("SendVerificationOTP for reset-password failed: %v", err)
	}
	resetCode := sender.lastData.OTP

	err = svc.ResetPassword(ctx, resetEmail, resetCode, "newSecurePassword123")
	if err != nil {
		t.Fatalf("ResetPassword with OTP failed: %v", err)
	}

	// 7. Verify hook interception on user create
	hookUser := &models.User{
		Base: models.Base{ID: models.NewID()},
		UserDto: models.UserDto{
			Email:         "hook.user@example.com",
			EmailVerified: false,
		},
	}
	if err := otpPlugin.Hooks().AfterUserCreate(ctx, hookUser); err != nil {
		t.Fatalf("AfterUserCreate hook failed: %v", err)
	}
	if sender.lastData.Email != "hook.user@example.com" {
		t.Fatalf("expected OTP to be dispatched for hook user, got %s", sender.lastData.Email)
	}
	_ = u
}

func TestEmailOTP_OverrideDefaultEmailVerification_SuppressesNormalEmail(t *testing.T) {
	db := setupTestDB(t)
	repos := gormauth.NewAuthRepos(db)
	txMgr := gormutil.NewGormTxManager(db)
	store := sec_storage.New()
	hooks := plugins.NewHookRegistry()
	sessionMgr := sessionsvc.NewManager(config.Session{ExpiresIn: 24 * time.Hour}, repos, repos, store, hooks)

	var defaultVerificationEmailSent bool
	authCfg := config.AuthConfig{
		Secret:  "test-secret-at-least-32-chars-long!",
		AppName: "Test App",
		Session: config.Session{ExpiresIn: 24 * time.Hour},
		EmailAndPassword: config.EmailAndPassword{
			RequireEmailVerification: true,
		},
		EmailVerification: config.EmailVerification{
			SendVerificationEmail: func(data config.EmailVerificationData, req *http.Request) error {
				defaultVerificationEmailSent = true
				return nil
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

	otpSender := &mockOTPSender{}
	otpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
		SendVerificationOTP:              otpSender.Send,
		OverrideDefaultEmailVerification: true,
	})

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Email OTP Test API", "1.0.0"))

	ictx := &plugins.InitContext{
		Ctx:            context.Background(),
		Api:            api,
		Config:         authCfg,
		TxManager:      txMgr,
		SessionManager: sessionMgr,
		IAuthRepos:     repos,
		Hooks:          hooks,
		IAuthSvc:       authService,
	}

	if err := otpPlugin.Init(ictx); err != nil {
		t.Fatalf("otpPlugin.Init failed: %v", err)
	}

	if !hooks.IsEmailVerificationOverridden() {
		t.Fatalf("expected HookRegistry to record email verification overridden")
	}

	// Sign up a new user via core authService
	ctx := context.Background()
	signUpInput := modeldtos.SignUpEmailInput{
		Email:    "override.user@example.com",
		Password: "SecurePassword123!",
		Name:     "Override Test",
	}

	signUpRes, err := authService.SignUpEmail(ctx, signUpInput, sessionsvc.Meta{})
	if err != nil {
		t.Fatalf("SignUpEmail failed: %v", err)
	}
	if signUpRes == nil || signUpRes.User.Email != "override.user@example.com" {
		t.Fatalf("unexpected signup result: %+v", signUpRes)
	}

	// Assert: The OTP email WAS sent
	if otpSender.lastData.Email != "override.user@example.com" {
		t.Fatalf("expected OTP to be dispatched, got %s", otpSender.lastData.Email)
	}
	if len(otpSender.lastData.OTP) != 6 {
		t.Fatalf("expected 6-digit OTP, got %s", otpSender.lastData.OTP)
	}

	// Assert: The default magic-link email WAS NOT sent (interrupted/suppressed)
	if defaultVerificationEmailSent {
		t.Fatalf("expected default verification email to be suppressed, but it was sent!")
	}
}

func TestEmailOTP_ChangeEmail(t *testing.T) {
	db := setupTestDB(t)
	repos := gormauth.NewAuthRepos(db)
	txMgr := gormutil.NewGormTxManager(db)
	store := sec_storage.New()
	hooks := plugins.NewHookRegistry()
	sessionMgr := sessionsvc.NewManager(config.Session{ExpiresIn: 24 * time.Hour}, repos, repos, store, hooks)

	sender := &mockOTPSender{}
	otpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
		SendVerificationOTP: sender.Send,
		OtpLength:           6,
		ExpiresIn:           5 * time.Minute,
		ChangeEmail: emailotpconfig.EmailOTPChangeEmailConfig{
			Enabled:            true,
			VerifyCurrentEmail: false,
		},
	})

	authCfg := config.AuthConfig{
		AppName: "Change Email Test",
		Secret:  "test-secret-at-least-32-characters-long!",
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Email OTP Change Email API", "1.0.0"))

	ictx := &plugins.InitContext{
		Ctx:            context.Background(),
		Api:            api,
		Config:         authCfg,
		TxManager:      txMgr,
		SessionManager: sessionMgr,
		IAuthRepos:     repos,
		Hooks:          plugins.NewHookRegistry(),
	}

	if err := otpPlugin.Init(ictx); err != nil {
		t.Fatalf("otpPlugin.Init failed: %v", err)
	}

	ctx := context.Background()

	// 1. Create a user
	oldEmail := "old.user@example.com"
	newEmail := "new.user@example.com"
	u := &models.User{
		UserDto: models.UserDto{
			Email:         oldEmail,
			EmailVerified: true,
			Name:          "Change Email Tester",
		},
	}
	createdUser, err := repos.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// 2. Request Email Change
	svc := otpPlugin.Service()
	if err := svc.RequestEmailChange(ctx, createdUser.ID, newEmail, nil, nil); err != nil {
		t.Fatalf("RequestEmailChange failed: %v", err)
	}

	if sender.lastData.Email != newEmail {
		t.Fatalf("expected OTP dispatched to %s, got %s", newEmail, sender.lastData.Email)
	}
	if sender.lastData.Type != emailotpconfig.OTPTypeChangeEmail {
		t.Fatalf("expected OTPType %s, got %s", emailotpconfig.OTPTypeChangeEmail, sender.lastData.Type)
	}
	changeOTP := sender.lastData.OTP

	// 3. Confirm Email Change
	updated, err := svc.ChangeEmail(ctx, createdUser.ID, newEmail, changeOTP)
	if err != nil {
		t.Fatalf("ChangeEmail failed: %v", err)
	}
	if updated == nil || updated.Email != newEmail {
		t.Fatalf("expected updated user email %s, got %+v", newEmail, updated)
	}

	// 4. Verify in DB
	userInDB, err := repos.FindUserByID(ctx, createdUser.ID)
	if err != nil || userInDB == nil {
		t.Fatalf("FindUserByID failed: %v", err)
	}
	if userInDB.Email != newEmail {
		t.Fatalf("expected DB user email %s, got %s", newEmail, userInDB.Email)
	}

	// 5. Verify credential account was created
	acc, err := repos.FindAccountByUserAndProvider(ctx, createdUser.ID, models.ProvCredential)
	if err != nil || acc == nil {
		t.Fatalf("expected credential account to be created, got err=%v, acc=%v", err, acc)
	}
	if acc.AccountID != createdUser.ID {
		t.Fatalf("expected credential account ID to match user ID %s, got %s", createdUser.ID, acc.AccountID)
	}

	// 6. Consuming the OTP a second time must fail
	if _, err := svc.ChangeEmail(ctx, createdUser.ID, newEmail, changeOTP); err == nil {
		t.Fatalf("expected second attempt with consumed OTP to fail, but it succeeded")
	}
}
