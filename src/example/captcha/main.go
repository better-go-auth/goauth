// Command captcha runs goauth with the captcha plugin (Cloudflare Turnstile): sign-up, sign-in and
// password-reset requests must carry the widget's token in the `x-captcha-response` header.
//
//	TURNSTILE_SECRET_KEY=... go run ./src/example/captcha   # http://localhost:8080/docs
//	go test ./src/example/captcha                            # the flow end to end, against a fake Turnstile
//
// Without TURNSTILE_SECRET_KEY the example uses Cloudflare's test secret that accepts every token.
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/captcha"
	captchaconfig "github.com/better-go-auth/goauth/src/plugins/captcha/config"
)

// turnstileTestSecret is Cloudflare's "always passes" test secret key.
const turnstileTestSecret = "1x0000000000000000000000000000000AA"

// newApp builds the example server. dbPath "" uses an in-memory database (tests); siteVerifyURL "" uses
// Cloudflare's real verification endpoint.
func newApp(dbPath, secretKey, siteVerifyURL string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin (default endpoints: /sign-up/email, /sign-in/email, /request-password-reset)
	captchaPlugin := captcha.New(captchaconfig.CaptchaConfig{
		Provider:  captchaconfig.CloudflareTurnstile,
		SecretKey: secretKey,
		// only the tests point this at a fake provider
		SiteVerifyURLOverride: siteVerifyURL,
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{captchaPlugin},
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
		dbPath = "captcha_example.db"
	}
	secret := os.Getenv("TURNSTILE_SECRET_KEY")
	if secret == "" {
		secret = turnstileTestSecret
	}
	app, err := newApp(dbPath, secret, "")
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
