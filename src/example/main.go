package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	bettergoauth "github.com/better-go-auth/goauth"
	loc_conf "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	"github.com/better-go-auth/goauth/src/plugins/org"
	"github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ConsoleEmailSender prints verification codes to stdout and remembers them for testing.
type ConsoleEmailSender struct {
	mu    sync.Mutex
	codes map[string]string
}

func (c *ConsoleEmailSender) SendVerificationCode(to, code string) error {
	c.mu.Lock()
	if c.codes == nil {
		c.codes = make(map[string]string)
	}
	c.codes[to] = code
	c.mu.Unlock()
	log.Printf("[EMAIL] Verification code for %s: %s", to, code)
	return nil
}

func (c *ConsoleEmailSender) GetLastCode(to string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codes[to]
}

func main() {
	dbFile := os.Getenv("SQLITE_DB")
	if dbFile == "" {
		dbFile = "example_auth.db"
	}

	db, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	if accessSecret == "" {
		accessSecret = "example-jwt-access-secret-32-chars-long!"
	}
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if refreshSecret == "" {
		refreshSecret = "example-jwt-refresh-secret-32-chars-long!"
	}

	mux := http.NewServeMux()
	apiConfig := huma.DefaultConfig("Better Go Auth Example Server", "1.0.0")
	api := humago.New(mux, apiConfig)
	jwt := loc_conf.SessionJWT{
		AccessSecret:     accessSecret,
		RefreshSecret:    refreshSecret,
		AccessExpiresIn:  time.Hour,
		RefreshExpiresIn: 24 * time.Hour,
	}

	emailSender := &ConsoleEmailSender{}
	adminPlugin, err := admin.NewWithGorm(db, admin.WithSessionConfig(loc_conf.SessionGoAuth{JWT: jwt}))
	if err != nil {
		log.Fatalf("failed to create admin plugin: %v", err)
	}

	orgPlugin, err := org.NewWithGorm(db, config.OrgConfig{
		OrgNeedsApproval: true,
		InvitaionConfig: config.InvitaionConfig{
			SendOrgInvitation: func(ctx context.Context, to, inviterName, orgName, inviteURL string) error {
				log.Printf("[EMAIL] inviter %s invites %s to org %s with link %s", inviterName, to, orgName, inviteURL)
				return nil
			},
		},
	})
	if err != nil {
		log.Fatalf("failed to create org plugin: %v", err)
	}

	accessTokenPlugin := accesstoken.New(
		accesstoken.WithSessionConfig(loc_conf.SessionGoAuth{JWT: jwt}),
		accesstoken.WithVerificationConfig(loc_conf.EmailVerification{
			GoAuth: loc_conf.EmailVerificationGoAuth{
				CodeExpiresIn: 15 * time.Minute,
				CodeSender:    emailSender,
			},
		}),
	)

	auth, err := bettergoauth.SetupGoAuth(api, bettergoauth.GoAuthOptions{
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
		},
	})
	if err != nil {
		log.Fatalf("failed to setup goauth: %v", err)
	}

	// Protected example endpoint
	type ProtectedInput struct{}
	type ProtectedOutput struct {
		Body struct {
			Message string `json:"message"`
			UserID  string `json:"userId"`
			Role    string `json:"role"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "Example_Protected",
		Method:      http.MethodGet,
		Path:        "/api/example/protected",
		Summary:     "Protected Example Endpoint",
		Tags:        []string{"Example"},
		Middlewares: huma.Middlewares{auth.MiddleWare.Authenticate()},
	}, func(ctx context.Context, input *ProtectedInput) (*ProtectedOutput, error) {
		out := &ProtectedOutput{}
		out.Body.Message = "Access granted to protected endpoint"
		if claims, valid := authenticator.SessionFromContext(ctx); valid {

			out.Body.UserID = claims.Session.UserID
			out.Body.Role = claims.User.Role
		}

		return out, nil
	})

	// Example endpoint that runs and tests the legacy auth flow using the access-token plugin
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
		testEmail := fmt.Sprintf("legacy-test-%d@example.com", time.Now().UnixNano())
		testPassword := "TestPassword123!"

		// 1. Register with email
		regRes, err := authSvc.RegisterWithEmail(ctx, models.RegisterClientInput{
			Email:     testEmail,
			Password:  testPassword,
			FirstName: "Legacy",
			LastName:  "Tester",
		})
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, fmt.Sprintf("Register failed: %v", err))
		}
		steps = append(steps, fmt.Sprintf("1. Registered user %s (ID: %s)", testEmail, regRes.User.ID))

		// 2. Verify account
		code := emailSender.GetLastCode(testEmail)
		if code == "" {
			return nil, huma.NewError(http.StatusInternalServerError, "Verification code not found")
		}
		steps = append(steps, fmt.Sprintf("2. Retrieved verification code: %s", code))

		verRes, err := authSvc.VerifyRegisteredUser(ctx, accesstokendtos.VerificationInput{
			Info: testEmail,
			Code: code,
		})
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, fmt.Sprintf("Verification failed: %v", err))
		}
		steps = append(steps, fmt.Sprintf("3. Verified account (Status: %s)", verRes.Body.AccountStatus))

		// 3. Login
		loginRes, err := authSvc.Login(ctx, accesstokendtos.LoginData{
			LoginInfo: testEmail,
			Password:  testPassword,
		})
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, fmt.Sprintf("Login failed: %v", err))
		}
		tokens := loginRes.Body.AuthTokens
		steps = append(steps, "4. Logged in and received JWT AccessToken + RefreshToken")

		// 4. Refresh token
		refreshRes, err := authSvc.ResetToken(ctx, tokens.RefreshToken)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, fmt.Sprintf("Token refresh failed: %v", err))
		}
		newTokens := refreshRes.Body.AuthTokens
		steps = append(steps, "5. Refreshed token successfully")

		// 5. Logout
		_, err = authSvc.Logout(ctx, newTokens.RefreshToken)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, fmt.Sprintf("Logout failed: %v", err))
		}
		steps = append(steps, "6. Logged out and revoked session")

		out := &TestLegacyAuthOutput{}
		out.Body.Success = true
		out.Body.Message = "Legacy authentication flow executed and verified successfully via access-token plugin"
		out.Body.UserID = regRes.User.ID
		out.Body.Email = testEmail
		out.Body.AccessToken = tokens.AccessToken
		out.Body.RefreshToken = tokens.RefreshToken
		out.Body.Steps = steps
		return out, nil
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Server listening on http://localhost:%s", port)
		log.Printf("OpenAPI documentation available at http://localhost:%s/docs", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}
	fmt.Println("Server gracefully stopped")
}
