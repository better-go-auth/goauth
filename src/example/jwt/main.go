// Command jwt runs goauth with the jwt plugin: a signed-in user gets a short-lived JWT for its session
// (GET /api/auth/token, or the `set-auth-jwt` header of GET /api/auth/get-session), and other services
// verify it offline with the public keys published at GET /api/auth/jwks. JWKSVerifier below is what such
// a service runs. SignServiceToken shows signing arbitrary claims from Go (server-only, not over HTTP).
//
//	go run ./src/example/jwt                  # http://localhost:8080/docs
//	go test ./src/example/jwt                 # runs the flow end to end
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/models/dtos"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	"github.com/golang-jwt/jwt/v5"
)

// Issuer and Audience are the iss / aud claims of the example's JWTs (both default to the base URL).
const (
	Issuer   = "https://auth.example.com"
	Audience = "https://api.example.com"
)

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database (the plugin adds a jwks table for its key pairs)
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: configure the plugin: issuer, audience, lifetime and the claims put in the token
	jwtPlugin := jwtplugin.New(jwtconfig.JWTConfig{
		JWT: jwtconfig.JWTClaimConfig{
			Issuer:         Issuer,
			Audience:       Audience,
			ExpirationTime: 10 * time.Minute, // default 15 minutes
			// DefinePayload replaces the default claims (the user object); "sub" is always added
			DefinePayload: func(session any) (map[string]any, error) {
				sw, ok := session.(*dtos.SessionWithUser)
				if !ok {
					return nil, errors.New("unexpected session type")
				}
				return map[string]any{
					"email":     sw.User.Email,
					"name":      sw.User.Name,
					"sessionId": sw.Session.ID,
				}, nil
			},
		},
	})
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{jwtPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a protected route of your own (session cookie)
	app.AddMeRoute()
	return app, nil
}

// JWKSVerifier verifies goauth JWTs in another service, using only the public JWKS endpoint. Keys are
// cached by kid and the JWKS is fetched again when a token names an unknown kid (key rotation).
type JWKSVerifier struct {
	JWKSURL  string
	Issuer   string
	Audience string
	HTTP     *http.Client

	mu   sync.Mutex
	keys map[string]ed25519.PublicKey
}

// jwks is the body of GET /jwks.
type jwks struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Alg string `json:"alg"`
		X   string `json:"x"`
	} `json:"keys"`
}

// refresh downloads the JWKS and replaces the cached keys.
func (v *JWKSVerifier) refresh(ctx context.Context) error {
	// Step 1: fetch the key set
	client := v.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	var set jwks
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("jwks: decode: %w", err)
	}
	// Step 2: keep the Ed25519 keys (the example uses the default EdDSA / Ed25519; ES256, ES512, PS256 and
	// RS256 keys have kty EC or RSA, see src/plugins/jwt/example.md)
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		keys[k.Kid] = ed25519.PublicKey(raw)
	}
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return nil
}

// key returns the public key for kid, fetching the JWKS when it is not cached yet.
func (v *JWKSVerifier) key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	v.mu.Lock()
	k, ok := v.keys[kid]
	v.mu.Unlock()
	if ok {
		return k, nil
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("jwks: unknown kid %q", kid)
}

// Verify checks the token's signature, algorithm, expiry, issuer and audience and returns its claims.
func (v *JWKSVerifier) Verify(ctx context.Context, token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims,
		// Step 1: pick the public key named by the token's kid header
		func(t *jwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)
			return v.key(ctx, kid)
		},
		// Step 2: only EdDSA, and the registered claims must match
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// SignServiceToken signs a JWT on the server, without a user session: here a short-lived token for an
// internal service. It is better-auth's server-only auth.api.signJWT, which goauth exposes to Go only
// (there is no /sign-jwt HTTP route). The token verifies against the same JWKS as user tokens.
func SignServiceToken(ctx context.Context, app *exkit.App, service string) (string, error) {
	// Step 1: get the initialized plugin from goauth (or keep the *jwtplugin.Plugin passed to SetupGoAuth)
	jwtPlugin, ok := app.Auth.Plugin(jwtplugin.PluginID).(*jwtplugin.Plugin)
	if !ok {
		return "", errors.New("jwt plugin not installed")
	}
	// Step 2: sign any claims; iat, exp, iss and aud are added from the plugin config unless overridden
	return jwtPlugin.SignJWT(ctx, map[string]any{
		"sub":   "service:" + service,
		"scope": "internal",
	}, &jwtplugin.SignJWTOptions{ExpirationTime: 5 * time.Minute})
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "jwt_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
