// Command email-otp runs goauth with the email-otp plugin: users get a one-time code by email to sign in
// (and sign up), to verify their email address and to reset their password.
//
//	go run ./src/example/email-otp            # http://localhost:8080/docs (codes are printed to the log)
//	go test ./src/example/email-otp           # runs the flow end to end
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests). The outbox holds the
// codes the plugin "emailed", keyed by OTP type ("sign-in", "email-verification", "forget-password").
func newApp(dbPath string) (*exkit.App, *exkit.Outbox, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, nil, err
	}
	// Step 2: the email sender. A real app sends an email here; the example records the code in the outbox
	outbox := &exkit.Outbox{}
	send := func(data emailotpconfig.SendVerificationOTPData, _ *http.Request) error {
		outbox.Put(string(data.Type), data.Email, data.OTP)
		return nil
	}
	// Step 3: configure the plugin (zero values = better-auth defaults: 6 digits, 5 minutes, 3 attempts)
	otpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
		SendVerificationOTP:      send,
		OtpLength:                6,
		ExpiresIn:                5 * time.Minute,
		AllowedAttempts:          3,
		SendVerificationOnSignUp: true, // email/password sign-ups get an "email-verification" code
	})
	// Step 4: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{otpPlugin},
	})
	if err != nil {
		return nil, nil, err
	}
	// Step 5: a protected route of your own
	app.AddMeRoute()
	return app, outbox, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "email_otp_example.db"
	}
	app, _, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
