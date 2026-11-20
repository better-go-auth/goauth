// Command siwe runs goauth with the siwe plugin: users sign in with an Ethereum wallet (Sign-In with
// Ethereum, EIP-4361). The wallet signs a message containing a server nonce; goauth checks the signature
// with secp256k1 public-key recovery and signs the wallet's user in.
//
//	go run ./src/example/siwe            # http://localhost:8080/docs
//	go test ./src/example/siwe           # runs the flow end to end with a generated wallet
package main

import (
	"context"
	"log"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/siwe"
	siweconfig "github.com/better-go-auth/goauth/src/plugins/siwe/config"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin. The default verifier checks EIP-191 signatures of externally owned
	// accounts; supply VerifyMessage for smart-contract wallets (EIP-1271) and ENSLookup for names.
	siwePlugin := siwe.New(siweconfig.SIWEConfig{
		// messages must be issued for this host (default: the BaseURL host)
		Domain: "localhost:8080",
		// new users get "<address>@wallet.example.com" as placeholder email
		EmailDomainName: "wallet.example.com",
		ENSLookup: func(_ context.Context, args siweconfig.ENSLookupArgs) (*siweconfig.ENSLookupResult, error) {
			// a real app resolves the ENS name / avatar of args.WalletAddress here
			return nil, nil
		},
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{siwePlugin},
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
		dbPath = "siwe_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
