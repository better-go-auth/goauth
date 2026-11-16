package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/better-go-auth/goauth/src/plugins"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/better-go-auth/goauth/src/plugins/email-otp/services"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type otpTestHarness struct {
	db         *gorm.DB
	repos      repo_interfaces.IAuthRepos
	mux        *http.ServeMux
	api        huma.API
	plugin     *emailotp.Plugin
	svc        *services.EmailOTPService
	sessionMgr *sessionsvc.Manager
	authSvc    *authsvc.Service
	sender     *multiOTPSender
}

type multiOTPSender struct {
	sent []emailotpconfig.SendVerificationOTPData
}

func (m *multiOTPSender) Send(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
	m.sent = append(m.sent, data)
	return nil
}

func (m *multiOTPSender) Last() emailotpconfig.SendVerificationOTPData {
	if len(m.sent) == 0 {
		return emailotpconfig.SendVerificationOTPData{}
	}
	return m.sent[len(m.sent)-1]
}

func setupIsolatedEmailOTPHarness(t *testing.T, cfg emailotpconfig.EmailOTPConfig, opts ...emailotp.Option) *otpTestHarness {
	t.Helper()
	// Step 1: Open isolated in-memory SQLite DB per test
	dsn := "file:email_otp_" + uuid.NewString() + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	if err := core_migration.NewGORMAdminMigrator(db).Migrate(context.Background()); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	// Step 2: Wire core repos, session manager, secondary storage, and hooks
	repos := gormauth.NewAuthRepos(db)
	txMgr := gormutil.NewGormTxManager(db)
	store, err := sec_storage.NewSecondaryStorage()
	if err != nil {
		t.Fatalf("failed to create secondary storage: %v", err)
	}
	hooks := plugins.NewHookRegistry()
	authCfg := config.AuthConfig{
		Secret:  "test-secret-at-least-32-chars-long!",
		AppName: "Email OTP Feature Test",
		Session: config.Session{ExpiresIn: 24 * time.Hour},
	}
	authCfg.SetDefaults()
	sessionMgr := sessionsvc.NewManager(authCfg.Session, repos, repos, store, hooks)
	authSvc := authsvc.New(authsvc.Deps{
		Config:   authCfg,
		Repos:    repos,
		Sessions: sessionMgr,
		Tx:       txMgr,
		Hooks:    hooks,
	})

	// Step 3: Initialize EmailOTP plugin and mount Huma routes
	sender := &multiOTPSender{}
	if cfg.SendVerificationOTP == nil {
		cfg.SendVerificationOTP = sender.Send
	}
	otpPlugin := emailotp.New(cfg, opts...)

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Email OTP API", "1.0.0"))
	ictx := &plugins.InitContext{
		Ctx:              context.Background(),
		Api:              api,
		Config:           authCfg,
		TxManager:        txMgr,
		SessionManager:   sessionMgr,
		IAuthRepos:       repos,
		IAuthSvc:         authSvc,
		Hooks:            hooks,
		SecondaryStorage: store,
	}
	if err := otpPlugin.Init(ictx); err != nil {
		t.Fatalf("otpPlugin.Init failed: %v", err)
	}

	return &otpTestHarness{
		db:         db,
		repos:      repos,
		mux:        mux,
		api:        api,
		plugin:     otpPlugin,
		svc:        otpPlugin.Service(),
		sessionMgr: sessionMgr,
		authSvc:    authSvc,
		sender:     sender,
	}
}

func doJSONReq(t *testing.T, handler http.Handler, method, path string, body any, headers ...map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("marshal request: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	for _, h := range headers {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestEmailOTP_GenerateOTP(t *testing.T) {
	ctx := context.Background()

	// Step 1: Configure custom GenerateOTP function and fallback when returning empty string
	callCount := 0
	h := setupIsolatedEmailOTPHarness(t, emailotpconfig.EmailOTPConfig{
		OtpLength: 8,
		GenerateOTP: func(data emailotpconfig.GenerateOTPData, req *http.Request) (string, error) {
			callCount++
			if data.Type == emailotpconfig.OTPTypeSignIn {
				return "CUSTOM-9999", nil
			}
			return "", nil // fall back to default 8-digit generator
		},
	})

	// Step 2: Sign-in OTP uses custom generator value
	err := h.svc.SendVerificationOTP(ctx, "gen@example.com", emailotpconfig.OTPTypeSignIn, nil)
	if err != nil {
		t.Fatalf("SendVerificationOTP failed: %v", err)
	}
	if h.sender.Last().OTP != "CUSTOM-9999" {
		t.Fatalf("expected custom OTP 'CUSTOM-9999', got %q", h.sender.Last().OTP)
	}
	if _, err := h.svc.SignIn(ctx, "gen@example.com", "CUSTOM-9999", sessionsvc.Meta{}); err != nil {
		t.Fatalf("SignIn with custom OTP failed: %v", err)
	}

	// Step 3: Email-verification OTP falls back to 8-digit default generator
	err = h.svc.SendVerificationOTP(ctx, "gen@example.com", emailotpconfig.OTPTypeEmailVerification, nil)
	if err != nil {
		t.Fatalf("SendVerificationOTP fallback failed: %v", err)
	}
	if len(h.sender.Last().OTP) != 8 {
		t.Fatalf("expected 8-digit fallback OTP, got %q", h.sender.Last().OTP)
	}
	if callCount != 2 {
		t.Fatalf("expected GenerateOTP to be called twice, got %d", callCount)
	}
}

func TestEmailOTP_AllowedAttempts_And_Expiry(t *testing.T) {
	ctx := context.Background()

	// Step 1: Configure AllowedAttempts = 2
	h := setupIsolatedEmailOTPHarness(t, emailotpconfig.EmailOTPConfig{
		AllowedAttempts: 2,
	})
	email := "attempts@example.com"
	_, err := h.repos.CreateUser(ctx, &models.User{
		Base:    models.Base{ID: models.NewID()},
		UserDto: models.UserDto{Email: email, Name: "Attempt User"},
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Step 2: Send OTP and submit 2 invalid attempts -> 3rd attempt should fail with TOO_MANY_ATTEMPTS (403)
	if err := h.svc.SendVerificationOTP(ctx, email, emailotpconfig.OTPTypeEmailVerification, nil); err != nil {
		t.Fatalf("SendVerificationOTP failed: %v", err)
	}
	validCode := h.sender.Last().OTP

	for i := 1; i <= 2; i++ {
		rec := doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/check-verification-otp", map[string]any{
			"email": email,
			"otp":   "000000",
			"type":  "email-verification",
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: expected 400 INVALID_OTP, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	// 3rd attempt (even with valid code!) must be rejected with 403 TOO_MANY_ATTEMPTS and delete token
	rec := doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/verify-email", map[string]any{
		"email": email,
		"otp":   validCode,
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("attempt 3: expected 403 TOO_MANY_ATTEMPTS, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "TOO_MANY_ATTEMPTS") {
		t.Fatalf("expected TOO_MANY_ATTEMPTS code in body: %s", rec.Body.String())
	}

	// Step 4: Subsequent check after deletion returns 400 INVALID_OTP
	rec = doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/check-verification-otp", map[string]any{
		"email": email,
		"otp":   validCode,
		"type":  "email-verification",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("after deletion: expected 400 INVALID_OTP, got %d: %s", rec.Code, rec.Body.String())
	}

	// Step 5: Test expired OTP returns ErrOTPExpired
	if err := h.svc.SendVerificationOTP(ctx, email, emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("SendVerificationOTP failed: %v", err)
	}
	expiredCode := h.sender.Last().OTP
	if err := h.db.Model(&models.Verification{}).
		Where("identifier = ?", "sign-in-otp-"+email).
		Update("expires_at", time.Now().Add(-1*time.Minute)).Error; err != nil {
		t.Fatalf("force expire failed: %v", err)
	}
	_, err = h.svc.SignIn(ctx, email, expiredCode, sessionsvc.Meta{})
	if !errors.Is(err, services.ErrOTPExpired) {
		t.Fatalf("expected ErrOTPExpired, got %v", err)
	}
}

func TestEmailOTP_StoreOTPModes_And_ResendStrategy(t *testing.T) {
	ctx := context.Background()

	// Step 1: StoreOTPPlain + ResendStrategyReuse -> reuses same OTP and extends expiry
	hPlain := setupIsolatedEmailOTPHarness(t, emailotpconfig.EmailOTPConfig{
		StoreOTP:       emailotpconfig.StoreOTPConfig{Mode: emailotpconfig.StoreOTPPlain},
		ResendStrategy: emailotpconfig.ResendStrategyReuse,
	})
	if err := hPlain.svc.SendVerificationOTP(ctx, "plain@example.com", emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("send 1 failed: %v", err)
	}
	otp1 := hPlain.sender.Last().OTP
	if err := hPlain.svc.SendVerificationOTP(ctx, "plain@example.com", emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("send 2 failed: %v", err)
	}
	otp2 := hPlain.sender.Last().OTP
	if otp1 != otp2 {
		t.Fatalf("expected plain+reuse to resend same OTP (%s != %s)", otp1, otp2)
	}
	if _, err := hPlain.svc.SignIn(ctx, "plain@example.com", otp2, sessionsvc.Meta{}); err != nil {
		t.Fatalf("SignIn with reused plain OTP failed: %v", err)
	}

	// Step 2: StoreOTPEncrypted + ResendStrategyReuse -> stored encrypted in DB, yet recoverable & reusable
	hEnc := setupIsolatedEmailOTPHarness(t, emailotpconfig.EmailOTPConfig{
		StoreOTP:       emailotpconfig.StoreOTPConfig{Mode: emailotpconfig.StoreOTPEncrypted},
		ResendStrategy: emailotpconfig.ResendStrategyReuse,
	})
	if err := hEnc.svc.SendVerificationOTP(ctx, "enc@example.com", emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("send enc 1 failed: %v", err)
	}
	encOtp1 := hEnc.sender.Last().OTP
	rec, err := hEnc.repos.FindVerificationValue(ctx, "sign-in-otp-enc@example.com")
	if err != nil || rec == nil {
		t.Fatalf("expected verification record in DB")
	}
	if strings.HasPrefix(rec.Value, encOtp1+":") {
		t.Fatalf("expected encrypted value in DB, got plaintext: %s", rec.Value)
	}
	if err := hEnc.svc.SendVerificationOTP(ctx, "enc@example.com", emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("send enc 2 failed: %v", err)
	}
	encOtp2 := hEnc.sender.Last().OTP
	if encOtp1 != encOtp2 {
		t.Fatalf("expected encrypted+reuse to resend same OTP (%s != %s)", encOtp1, encOtp2)
	}
	if _, err := hEnc.svc.SignIn(ctx, "enc@example.com", encOtp2, sessionsvc.Meta{}); err != nil {
		t.Fatalf("SignIn with encrypted OTP failed: %v", err)
	}

	// Step 3: StoreOTPHashed + ResendStrategyReuse -> falls back to rotate (new OTP) and verifies properly
	hHash := setupIsolatedEmailOTPHarness(t, emailotpconfig.EmailOTPConfig{
		StoreOTP:       emailotpconfig.StoreOTPConfig{Mode: emailotpconfig.StoreOTPHashed},
		ResendStrategy: emailotpconfig.ResendStrategyReuse,
	})
	if err := hHash.svc.SendVerificationOTP(ctx, "hash@example.com", emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("send hash 1 failed: %v", err)
	}
	hashOtp1 := hHash.sender.Last().OTP
	recHash, err := hHash.repos.FindVerificationValue(ctx, "sign-in-otp-hash@example.com")
	if err != nil || recHash == nil || strings.HasPrefix(recHash.Value, hashOtp1+":") {
		t.Fatalf("expected hashed value in DB, got: %+v", recHash)
	}
	if err := hHash.svc.SendVerificationOTP(ctx, "hash@example.com", emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("send hash 2 failed: %v", err)
	}
	hashOtp2 := hHash.sender.Last().OTP
	if _, err := hHash.svc.SignIn(ctx, "hash@example.com", hashOtp2, sessionsvc.Meta{}); err != nil {
		t.Fatalf("SignIn with hashed OTP failed: %v", err)
	}

	// Step 4: Custom Encrypt/Decrypt + ResendStrategyRotate
	hCustom := setupIsolatedEmailOTPHarness(t, emailotpconfig.EmailOTPConfig{
		StoreOTP: emailotpconfig.StoreOTPConfig{
			Encrypt: func(otp string) (string, error) { return "ENC[" + otp + "]", nil },
			Decrypt: func(enc string) (string, error) {
				return strings.TrimSuffix(strings.TrimPrefix(enc, "ENC["), "]"), nil
			},
		},
		ResendStrategy: emailotpconfig.ResendStrategyRotate,
	})
	if err := hCustom.svc.SendVerificationOTP(ctx, "custom@example.com", emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("send custom failed: %v", err)
	}
	customOtp := hCustom.sender.Last().OTP
	recCustom, _ := hCustom.repos.FindVerificationValue(ctx, "sign-in-otp-custom@example.com")
	if recCustom == nil || !strings.HasPrefix(recCustom.Value, "ENC["+customOtp+"]:") {
		t.Fatalf("expected custom encrypted DB value, got %+v", recCustom)
	}
	if _, err := hCustom.svc.SignIn(ctx, "custom@example.com", customOtp, sessionsvc.Meta{}); err != nil {
		t.Fatalf("SignIn with custom encrypted OTP failed: %v", err)
	}
}

func TestEmailOTP_RateLimit_And_HTTPHandlers(t *testing.T) {
	ctx := context.Background()

	// Step 1: Configure RateLimit (Max: 2 per 60s window) and ChangeEmail enabled with VerifyCurrentEmail
	h := setupIsolatedEmailOTPHarness(t, emailotpconfig.EmailOTPConfig{
		ChangeEmail: emailotpconfig.EmailOTPChangeEmailConfig{
			Enabled:            true,
			VerifyCurrentEmail: true,
		},
	}, emailotp.WithRateLimit(60*time.Second, 2))

	// Step 2: Trigger rate limit on /email-otp/send-verification-otp (2 allowed, 3rd returns 429)
	for i := 1; i <= 2; i++ {
		rec := doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/send-verification-otp", map[string]any{
			"email": "rl@example.com",
			"type":  "sign-in",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/send-verification-otp", map[string]any{
		"email": "rl@example.com",
		"type":  "sign-in",
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3: expected 429 Too Many Requests, got %d: %s", rec.Code, rec.Body.String())
	}

	// Step 3: Sign in via /sign-in/email-otp HTTP handler using last sent OTP
	signInOTP := h.sender.Last().OTP
	rec = doJSONReq(t, h.mux, http.MethodPost, "/api/auth/sign-in/email-otp", map[string]any{
		"email": "rl@example.com",
		"otp":   signInOTP,
		"name":  "RL User",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("sign-in/email-otp failed: %d: %s", rec.Code, rec.Body.String())
	}
	var signInBody modeldtos.SignInResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &signInBody); err != nil {
		t.Fatalf("decode sign-in response: %v", err)
	}
	if signInBody.Token == "" || signInBody.User == nil || signInBody.User.Name != "RL User" {
		t.Fatalf("unexpected sign-in response: %+v", signInBody)
	}

	// Step 4: Test /email-otp/request-password-reset and /email-otp/reset-password HTTP handlers
	rec = doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/request-password-reset", map[string]any{
		"email": "rl@example.com",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("request-password-reset failed: %d: %s", rec.Code, rec.Body.String())
	}
	resetOTP := h.sender.Last().OTP

	rec = doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/reset-password", map[string]any{
		"email":    "rl@example.com",
		"otp":      resetOTP,
		"password": "NewStrongPassword123!",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("reset-password failed: %d: %s", rec.Code, rec.Body.String())
	}

	// Step 5: Test ChangeEmail with VerifyCurrentEmail: true via HTTP handlers
	authHdr := map[string]string{"Authorization": "Bearer " + signInBody.Token}
	// Request without current OTP fails
	rec = doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/request-email-change", map[string]any{
		"newEmail": "rl-new@example.com",
	}, authHdr)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when current OTP omitted, got %d: %s", rec.Code, rec.Body.String())
	}

	// Dispatch current-email verification OTP directly via service (within rate limit)
	if err := h.svc.SendVerificationOTP(ctx, "rl@example.com", emailotpconfig.OTPTypeEmailVerification, nil); err != nil {
		t.Fatalf("send current email otp failed: %v", err)
	}
	currOTP := h.sender.Last().OTP
	rec = doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/request-email-change", map[string]any{
		"newEmail": "rl-new@example.com",
		"otp":      currOTP,
	}, authHdr)
	if rec.Code != http.StatusOK {
		t.Fatalf("request-email-change with current OTP failed: %d: %s", rec.Code, rec.Body.String())
	}
	newEmailOTP := h.sender.Last().OTP
	rec = doJSONReq(t, h.mux, http.MethodPost, "/api/auth/email-otp/change-email", map[string]any{
		"newEmail": "rl-new@example.com",
		"otp":      newEmailOTP,
	}, authHdr)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-email failed: %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEmailOTP_DisableSignUp_And_DisableChangeEmail(t *testing.T) {
	ctx := context.Background()

	// Step 1: DisableSignUp: true, ChangeEmail.Enabled: false
	h := setupIsolatedEmailOTPHarness(t, emailotpconfig.EmailOTPConfig{
		DisableSignUp: true,
		ChangeEmail: emailotpconfig.EmailOTPChangeEmailConfig{
			Enabled: false,
		},
	})

	// Step 2: Sending sign-in or forget-password OTP for unknown user must silently succeed without dispatching email
	if err := h.svc.SendVerificationOTP(ctx, "unknown@example.com", emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("SendVerificationOTP failed: %v", err)
	}
	if len(h.sender.sent) != 0 {
		t.Fatalf("expected 0 OTP emails sent when DisableSignUp=true for unknown user, got %d", len(h.sender.sent))
	}
	if err := h.svc.SendVerificationOTP(ctx, "unknown@example.com", emailotpconfig.OTPTypeForgetPassword, nil); err != nil {
		t.Fatalf("SendVerificationOTP forget-password failed: %v", err)
	}
	if len(h.sender.sent) != 0 {
		t.Fatalf("expected 0 forget-password OTP emails sent for unknown user, got %d", len(h.sender.sent))
	}
	_, err := h.svc.SignIn(ctx, "unknown@example.com", "123456", sessionsvc.Meta{})
	if !errors.Is(err, services.ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP when DisableSignUp=true for unknown user, got %v", err)
	}

	// Existing user can still sign in with OTP when DisableSignUp=true
	u, err := h.repos.CreateUser(ctx, &models.User{
		Base:    models.Base{ID: models.NewID()},
		UserDto: models.UserDto{Email: "existing@example.com", Name: "Existing"},
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if err := h.svc.SendVerificationOTP(ctx, u.Email, emailotpconfig.OTPTypeSignIn, nil); err != nil {
		t.Fatalf("SendVerificationOTP for existing user failed: %v", err)
	}
	if len(h.sender.sent) != 1 {
		t.Fatalf("expected 1 OTP sent for existing user, got %d", len(h.sender.sent))
	}
	if _, err := h.svc.SignIn(ctx, u.Email, h.sender.Last().OTP, sessionsvc.Meta{}); err != nil {
		t.Fatalf("existing user OTP SignIn with DisableSignUp=true failed: %v", err)
	}

	// Step 3: RequestEmailChange must fail with ErrChangeEmailDisabled when ChangeEmail.Enabled=false
	err = h.svc.RequestEmailChange(ctx, u.ID, "other@example.com", nil, nil)
	if autherr.AsAuthError(err) == nil || !errors.Is(err, services.ErrChangeEmailDisabled) {
		t.Fatalf("expected ErrChangeEmailDisabled, got %v", err)
	}
}
