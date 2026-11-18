// Command two-factor runs goauth with the two-factor plugin: users turn on a second factor (TOTP from an
// authenticator app, a one-time code sent by email, or a backup code) and every password sign-in then
// asks for it before a session is created.
//
//	go run ./src/example/two-factor          # http://localhost:8080/docs
//	go test ./src/example/two-factor         # runs the flow end to end
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests). The one-time codes
// the plugin sends are recorded in outbox (and logged) instead of being emailed.
func newApp(dbPath string, outbox *exkit.Outbox) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin. Issuer is the name authenticator apps show; SendOTP enables the
	// email/SMS code method (send it with your mailer; here it goes to the outbox)
	twoFactorPlugin := twofactor.New(tfconfig.Config{
		Issuer: "GoAuth Example",
		OTPOptions: tfconfig.OTPOptions{
			SendOTP: func(_ context.Context, data tfconfig.SendOTPData, _ *http.Request) error {
				outbox.Put("two-factor-otp", data.User.Email, data.OTP)
				return nil
			},
		},
	})
	// Step 3: set goauth up with the plugin (AppName is the issuer of /two-factor/get-totp-uri)
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{twoFactorPlugin},
		Configure: func(c *config.AuthConfig) {
			c.AppName = "GoAuth Example"
		},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a protected route of your own
	app.AddMeRoute()
	return app, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "two_factor_example.db"
	}
	app, err := newApp(dbPath, &exkit.Outbox{})
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
