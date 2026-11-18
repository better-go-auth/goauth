// Command device-authorization runs goauth with the device-authorization plugin (OAuth 2.0 Device
// Authorization Grant, RFC 8628): a CLI or TV asks for a code, the user approves it in the browser, and
// the device receives a session token it uses as a bearer token.
//
//	go run ./src/example/device-authorization            # http://localhost:8080/docs
//	go test ./src/example/device-authorization           # runs the flow end to end
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	deviceauthorization "github.com/better-go-auth/goauth/src/plugins/device-authorization"
	daconfig "github.com/better-go-auth/goauth/src/plugins/device-authorization/config"
)

// knownClients are the client_ids allowed to start the device flow.
var knownClients = map[string]bool{"example-cli": true}

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin (zero values = better-auth defaults: 30 min codes, 5 s polling)
	devicePlugin := deviceauthorization.New(daconfig.DeviceAuthorizationConfig{
		ExpiresIn: 10 * time.Minute,
		Interval:  time.Second,
		// only known clients may ask for codes
		ValidateClient: func(_ context.Context, clientID string) (bool, error) {
			return knownClients[clientID], nil
		},
		// log every request (audit, metrics, ...)
		OnDeviceAuthRequest: func(_ context.Context, clientID string, scope *string) error {
			log.Printf("[device] code requested by %s", clientID)
			return nil
		},
		// the page of this app where users type the code (see devicePage)
		VerificationURI: "/device",
	})
	// Step 3: the bearer plugin lets the device send the token as "Authorization: Bearer <token>"
	unsigned := false
	bearerPlugin := bearer.New(bearerconfig.BearerConfig{RequireSignature: &unsigned})
	// Step 4: set goauth up with both plugins
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{devicePlugin, bearerPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 5: the verification page and a protected route of your own
	app.Mux.HandleFunc("GET /device", devicePage)
	app.AddMeRoute()
	return app, nil
}

// devicePage is a minimal verification page. A real one asks the signed-in user to confirm the code:
// GET /api/auth/device?user_code=... (claims it), then POST /api/auth/device/approve or /device/deny.
func devicePage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><title>Connect a device</title>
<p>Confirm the code shown on your device: <b id="code"></b></p>
<button id="approve">Approve</button> <button id="deny">Deny</button>
<script>
const code = new URLSearchParams(location.search).get("user_code") || "";
document.getElementById("code").textContent = code;
// claim the code for the signed-in user
fetch("/api/auth/device?user_code=" + encodeURIComponent(code), {credentials: "include"});
for (const action of ["approve", "deny"]) {
  document.getElementById(action).onclick = () => fetch("/api/auth/device/" + action, {
    method: "POST", credentials: "include", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({userCode: code}),
  }).then((r) => r.json()).then((b) => alert(JSON.stringify(b)));
}
</script>`))
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "device_authorization_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
