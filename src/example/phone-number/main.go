// Command phone-number runs goauth with the phone-number plugin: users verify a phone number with an SMS
// code (signing up on first verification), sign in with phone number + password, and reset their
// password by SMS.
//
//	go run ./src/example/phone-number         # http://localhost:8080/docs (SMS codes are printed to the log)
//	go test ./src/example/phone-number        # runs the flow end to end
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	phonenumber "github.com/better-go-auth/goauth/src/plugins/phone-number"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
)

// e164 accepts numbers like +15551234567.
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// newApp builds the example server. dbPath "" uses an in-memory database (tests). The outbox holds the
// codes the plugin "texted": kind "sms" for verification codes, "sms-reset" for password reset codes.
func newApp(dbPath string) (*exkit.App, *exkit.Outbox, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, nil, err
	}
	// Step 2: the SMS senders. A real app calls its SMS provider here; the example records the codes
	outbox := &exkit.Outbox{}
	sendOTP := func(data phoneconfig.OTPData, _ *http.Request) error {
		outbox.Put("sms", data.PhoneNumber, data.Code)
		return nil
	}
	sendResetOTP := func(data phoneconfig.OTPData, _ *http.Request) error {
		outbox.Put("sms-reset", data.PhoneNumber, data.Code)
		return nil
	}
	// Step 3: configure the plugin (zero values = better-auth defaults: 6 digits, 300s, 3 attempts)
	phonePlugin := phonenumber.New(phoneconfig.PhoneNumberConfig{
		SendOTP:              sendOTP,
		SendPasswordResetOTP: sendResetOTP,
		PhoneNumberValidator: e164.MatchString,
		// verifying an unknown number creates the user; email is required, so give it a placeholder
		SignUpOnVerification: &phoneconfig.SignUpOnVerification{
			GetTempEmail: func(phone string) string { return strings.TrimPrefix(phone, "+") + "@phone.example.com" },
		},
	})
	// Step 4: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{phonePlugin},
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
		dbPath = "phone_number_example.db"
	}
	app, _, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
