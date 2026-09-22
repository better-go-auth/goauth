package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	bettergoauth "github.com/better-go-auth/goauth"
	loc_conf "github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
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

// ConsoleEmailSender prints verification codes to stdout for local development.
type ConsoleEmailSender struct{}

func (c *ConsoleEmailSender) SendVerificationCode(to, code string) error {
	log.Printf("[EMAIL] Verification code for %s: %s", to, code)
	return nil
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
	jwt := loc_conf.JwtVar{
		AccessSecret:     accessSecret,
		RefreshSecret:    refreshSecret,
		AccessExpireMin:  60,
		RefreshExpireMin: 1440,
	}

	emailSender := &ConsoleEmailSender{}
	adminPlugin, err := admin.NewWithGorm(db, admin.WithSessionConfig(loc_conf.SessionConfig{JwtVar: jwt}))
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

	auth, err := bettergoauth.SetupGoAuth(api, bettergoauth.GoAuthOptions{
		Conn: db,
		AuthConfig: loc_conf.AuthConfig{
			EmailVerification: loc_conf.EmailVerification{
				ExpiresIn:              15 * time.Minute,
				VerificationCodeSender: emailSender,
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
			out.Body.Role = claims.Session.Role
		}

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
