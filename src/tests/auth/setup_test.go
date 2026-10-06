package auth_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	bettergoauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

func TestSetupGoAuth_ValidationAndDefaults(t *testing.T) {
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Test API", "1.0.0"))

	t.Run("Fails when API is nil", func(t *testing.T) {
		_, err := bettergoauth.SetupGoAuth(nil, bettergoauth.GoAuthOptions{})
		if err == nil {
			t.Fatalf("Expected error when API is nil, got nil")
		}
	})

	t.Run("Fails when Conn is nil", func(t *testing.T) {
		opts := bettergoauth.GoAuthOptions{}
		opts.Secret = "secret"
		_, err := bettergoauth.SetupGoAuth(api, opts)
		if err == nil {
			t.Fatalf("Expected error when Conn is nil, got nil")
		}
	})

	t.Run("Fails when no secret is configured", func(t *testing.T) {
		t.Setenv(config.SecretEnvVar, "")
		env := helpers.SetupTestEnv(t, true)
		opts := bettergoauth.GoAuthOptions{
			Conn: env.DB,
		}
		_, err := bettergoauth.SetupGoAuth(api, opts)
		if err == nil {
			t.Fatalf("Expected error when no secret is configured, got nil")
		}
	})

	t.Run("Applies sensible defaults", func(t *testing.T) {
		opts := config.AuthConfig{}
		opts.Secret = "secret"
		opts.SetDefaults()

		jwt := opts.GoAuth.Session.JWT
		if opts.BasePath != "/api/auth" {
			t.Errorf("Expected BasePath '/api/auth', got %q", opts.BasePath)
		}
		if jwt.AccessExpiresIn != time.Hour || jwt.RefreshExpiresIn != 7*24*time.Hour {
			t.Errorf("unexpected JWT lifetimes %v / %v", jwt.AccessExpiresIn, jwt.RefreshExpiresIn)
		}
		if jwt.AccessSecret == "" || jwt.RefreshSecret == "" || jwt.AccessSecret == jwt.RefreshSecret {
			t.Errorf("JWT secrets must be derived and differ: %q %q", jwt.AccessSecret, jwt.RefreshSecret)
		}
		if opts.EmailVerification.GoAuth.CodeExpiresIn != 15*time.Minute {
			t.Errorf("Expected CodeExpiresIn 15m, got %v", opts.EmailVerification.GoAuth.CodeExpiresIn)
		}
	})
}

func TestRevocationStore_IsRevoked(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ctx := context.Background()

	testEmail := "test_rev_user@example.com"
	testUser := models.User{
		UserDto: models.UserDto{
			FirstName:     "Rev",
			LastName:      "User",
			Email:         testEmail,
			EmailVerified: true,
			Role:          enums.User,
		},
	}
	if err := env.DB.Create(&testUser).Error; err != nil {
		t.Fatalf("Failed to create test user for revocation tests: %v", err)
	}

	revConf := env.Options.GoAuth.Session.JWT
	revConf.CheckRevocation = true
	revStore := providers.NewRevocationStore(env.DB, env.SecondaryStorage, revConf)

	t.Run("Empty sessionID is not revoked", func(t *testing.T) {
		revoked, err := revStore.IsRevoked(ctx, "")
		if err != nil || revoked {
			t.Fatalf("Expected false, nil for empty sessionID; got revoked=%v, err=%v", revoked, err)
		}
	})

	t.Run("Active session is not revoked", func(t *testing.T) {
		sessionID := ulid.Make().String()
		_, err := env.Auth.IAuthServices.CreateSession(ctx, sessionID, string(enums.User), testUser.ID, nil)
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}

		revoked, err := revStore.IsRevoked(ctx, sessionID)
		if err != nil {
			t.Fatalf("IsRevoked returned error: %v", err)
		}
		if revoked {
			t.Fatalf("Expected active session to not be revoked")
		}
	})

	t.Run("Non-existent or deleted session is revoked", func(t *testing.T) {
		revoked, err := revStore.IsRevoked(ctx, "non_existent_session_id")
		if err != nil {
			t.Fatalf("IsRevoked returned error: %v", err)
		}
		if !revoked {
			t.Fatalf("Expected non-existent session to be reported as revoked")
		}
	})

	t.Run("Expired session in DB is revoked", func(t *testing.T) {
		sessionID := ulid.Make().String()
		sess := models.Session{
			Base:      models.Base{ID: sessionID},
			Token:     "refresh-hash-" + sessionID,
			UserID:    testUser.ID,
			ExpiresAt: time.Now().Add(-1 * time.Hour), // expired in past
		}
		if err := env.DB.Create(&sess).Error; err != nil && err != gorm.ErrRecordNotFound {
			t.Fatalf("Failed to create session: %v", err)
		}

		revoked, err := revStore.IsRevoked(ctx, sessionID)
		if err != nil {
			t.Fatalf("IsRevoked returned error: %v", err)
		}
		if !revoked {
			t.Fatalf("Expected expired session to be revoked")
		}
	})
}
