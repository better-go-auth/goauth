package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bettergoauth "github.com/better-go-auth/goauth"
	loc_conf "github.com/better-go-auth/goauth/src/config"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/better-go-auth/goauth/src/models"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestExample_LegacyAuthEndpoint(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open sqlite in-memory db: %v", err)
	}

	migrator := core_migration.NewGORMAdminMigrator(db)
	if err := migrator.Migrate(context.Background()); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	mux := http.NewServeMux()
	apiConfig := huma.DefaultConfig("Example Test Server", "1.0.0")
	api := humago.New(mux, apiConfig)

	jwt := loc_conf.SessionJWT{
		AccessSecret:     "test-secret-must-be-32-chars-long!",
		RefreshSecret:    "test-refresh-must-be-32-chars-long!",
		AccessExpiresIn:  time.Hour,
		RefreshExpiresIn: 24 * time.Hour,
	}

	emailSender := &ConsoleEmailSender{}
	adminPlugin, err := admin.NewWithGorm(db, admin.WithSessionConfig(loc_conf.SessionGoAuth{JWT: jwt}))
	if err != nil {
		t.Fatalf("failed to create admin plugin: %v", err)
	}

	orgPlugin, err := org.NewWithGorm(db, orgconfig.OrgConfig{OrgNeedsApproval: false})
	if err != nil {
		t.Fatalf("failed to create org plugin: %v", err)
	}

	accessTokenPlugin := accesstoken.New(accesstokenconfig.AccessTokenConfig{
		Session: loc_conf.SessionGoAuth{JWT: jwt},
		Verification: loc_conf.EmailVerification{
			GoAuth: loc_conf.EmailVerificationGoAuth{
				CodeExpiresIn: 15 * time.Minute,
				CodeSender:    emailSender,
			},
		},
	})

	emailOtpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
		SendVerificationOTP:              emailSender.SendOTP,
		ExpiresIn:                        15 * time.Minute,
		SendVerificationOnSignUp:         true,
		OverrideDefaultEmailVerification: true,
	})

	_, err = bettergoauth.SetupGoAuth(api, bettergoauth.GoAuthOptions{
		Conn: db,
		AuthConfig: loc_conf.AuthConfig{
			EmailVerification: loc_conf.EmailVerification{
				GoAuth: loc_conf.EmailVerificationGoAuth{
					CodeExpiresIn: 15 * time.Minute,
					CodeSender:    emailSender,
				},
			},
			GoAuth: loc_conf.GoAuthConfig{
				Session: loc_conf.SessionGoAuth{JWT: jwt},
			},
		},
		Plugins: []plugin.Plugin{
			adminPlugin,
			orgPlugin,
			accessTokenPlugin,
			emailOtpPlugin,
		},
	})
	if err != nil {
		t.Fatalf("failed to setup goauth: %v", err)
	}

	// Register the test endpoint as done in main.go
	type TestLegacyAuthOutput struct {
		Body struct {
			Success      bool     `json:"success"`
			Message      string   `json:"message"`
			UserID       string   `json:"userId"`
			Email        string   `json:"email"`
			AccessToken  string   `json:"accessToken"`
			RefreshToken string   `json:"refreshToken"`
			Steps        []string `json:"steps"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "Example_TestLegacyAuth",
		Method:      http.MethodGet,
		Path:        "/api/example/test-legacy-auth",
		Summary:     "Run and test legacy auth flow via access-token plugin",
		Tags:        []string{"Example"},
	}, func(ctx context.Context, input *struct{}) (*TestLegacyAuthOutput, error) {
		steps := []string{}
		authSvc := accessTokenPlugin.AuthService()
		testEmail := "test-legacy-example@example.com"
		testPassword := "TestPassword123!"

		// 1. Register with email
		regRes, err := authSvc.RegisterWithEmail(ctx, models.RegisterClientInput{
			Email:     testEmail,
			Password:  testPassword,
			FirstName: "Legacy",
			LastName:  "Tester",
		})
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		steps = append(steps, "1. Registered user")

		// 2. Verify account via email-otp plugin
		otpCode := emailSender.GetLastCode(testEmail)
		if otpCode == "" {
			return nil, huma.NewError(http.StatusInternalServerError, "no OTP found for user")
		}
		_, _, err = emailOtpPlugin.Service().VerifyEmail(ctx, testEmail, otpCode, sessionsvc.Meta{}, nil)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		steps = append(steps, "2. Verified account via email-otp plugin")

		// 3. Login
		loginRes, err := authSvc.Login(ctx, accesstokendtos.LoginData{
			LoginInfo: testEmail,
			Password:  testPassword,
		})
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		tokens := loginRes.Body.AuthTokens
		steps = append(steps, "3. Logged in and received tokens")

		// 4. Refresh token
		refreshRes, err := authSvc.ResetToken(ctx, tokens.RefreshToken)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		newTokens := refreshRes.Body.AuthTokens
		steps = append(steps, "4. Refreshed token")

		// 5. Logout
		_, err = authSvc.Logout(ctx, newTokens.RefreshToken)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		steps = append(steps, "5. Logged out and revoked session")

		out := &TestLegacyAuthOutput{}
		out.Body.Success = true
		out.Body.Message = "Flow executed"
		out.Body.UserID = regRes.User.ID
		out.Body.Email = testEmail
		out.Body.AccessToken = tokens.AccessToken
		out.Body.RefreshToken = tokens.RefreshToken
		out.Body.Steps = steps
		return out, nil
	})

	// Make HTTP request to test endpoint
	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/example/test-legacy-auth")
	if err != nil {
		t.Fatalf("GET /api/example/test-legacy-auth failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var res struct {
		Success      bool     `json:"success"`
		Message      string   `json:"message"`
		UserID       string   `json:"userId"`
		Email        string   `json:"email"`
		AccessToken  string   `json:"accessToken"`
		RefreshToken string   `json:"refreshToken"`
		Steps        []string `json:"steps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !res.Success {
		t.Fatalf("expected success to be true")
	}
	if res.AccessToken == "" {
		t.Fatalf("expected access token to be present")
	}
	if len(res.Steps) != 5 {
		t.Fatalf("expected 5 steps, got %d", len(res.Steps))
	}
}
