// Command one-tap runs goauth with the one-tap plugin: the page at / shows Google's One Tap prompt and
// posts the ID token Google returns to POST /api/auth/one-tap/callback, which signs the user in.
//
//	GOOGLE_CLIENT_ID=... go run ./src/example/one-tap   # http://localhost:8080
//	go test ./src/example/one-tap                        # the flow end to end, against a fake Google JWKS
//
// Add http://localhost:8080 to the "Authorized JavaScript origins" of the Google OAuth client.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	onetap "github.com/better-go-auth/goauth/src/plugins/one-tap"
	onetapconfig "github.com/better-go-auth/goauth/src/plugins/one-tap/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests); jwksURL "" verifies
// ID tokens against Google's real key set.
func newApp(dbPath, clientID, jwksURL string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin: the Google client ID the ID tokens must be issued for
	oneTapPlugin := onetap.New(onetapconfig.OneTapConfig{
		ClientID: clientID,
		// JWKSURL is only set by the tests (a fake Google); empty = https://www.googleapis.com/oauth2/v3/certs
		JWKSURL: jwksURL,
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{oneTapPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a protected route of your own and the page showing the One Tap prompt
	app.AddMeRoute()
	app.Mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, page, clientID)
	})
	return app, nil
}

// page loads Google Identity Services and sends the credential (the ID token) to goauth.
const page = `<!doctype html>
<html>
<body>
  <h1>goauth one-tap example</h1>
  <pre id="out">waiting for Google One Tap...</pre>
  <script src="https://accounts.google.com/gsi/client" async></script>
  <script>
    window.onload = function () {
      google.accounts.id.initialize({
        client_id: %q,
        callback: async function (response) {
          const res = await fetch("/api/auth/one-tap/callback", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ idToken: response.credential }),
          });
          const me = await fetch("/api/example/me");
          document.getElementById("out").textContent =
            JSON.stringify(await res.json(), null, 2) + "\n\n/api/example/me: " + JSON.stringify(await me.json(), null, 2);
        },
      });
      google.accounts.id.prompt();
    };
  </script>
</body>
</html>`

func main() {
	// Step 1: the Google client ID
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	if clientID == "" {
		log.Println("GOOGLE_CLIENT_ID is not set: Google will not show the One Tap prompt")
	}
	// Step 2: the server
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "one_tap_example.db"
	}
	app, err := newApp(dbPath, clientID, "")
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
