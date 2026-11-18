package compattest

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	bearer "github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// TestGoMirror_JWT mirrors src/tests/compat/client/test-jwt.mjs in pure Go.
func TestGoMirror_JWT(t *testing.T) {
	s := NewServer(t,
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(jwtplugin.New(jwtconfig.DefaultConfig())),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	c := newBearerTestClient(s.URL)
	email := fmt.Sprintf("go-jwt-%d@example.com", time.Now().UnixNano())
	password := "Password123!"
	name := "Official Client JWT User"

	// [1] GET /jwks and import Ed25519 public key
	jwksRes := c.get(t, "/api/auth/jwks")
	require.Equal(t, http.StatusOK, jwksRes.Status, string(jwksRes.Body))
	var jwksBody struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	jwksRes.JSON(t, &jwksBody)
	require.NotEmpty(t, jwksBody.Keys)
	jwk := jwksBody.Keys[0]
	require.Equal(t, "OKP", jwk.Kty)
	require.Equal(t, "Ed25519", jwk.Crv)
	require.NotEmpty(t, jwk.X)
	require.NotEmpty(t, jwk.Kid)
	pubBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	require.NoError(t, err)
	pubKey := ed25519.PublicKey(pubBytes)

	verifyEdDSA := func(tokStr string) jwt.MapClaims {
		t.Helper()
		parsed, err := jwt.Parse(tokStr, func(tok *jwt.Token) (any, error) {
			if _, ok := tok.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected alg: %v", tok.Header["alg"])
			}
			return pubKey, nil
		})
		require.NoError(t, err)
		require.True(t, parsed.Valid)
		claims, ok := parsed.Claims.(jwt.MapClaims)
		require.True(t, ok)
		return claims
	}

	// [2] signUp.email
	upRes := c.post(t, "/api/auth/sign-up/email", map[string]any{
		"email":    email,
		"password": password,
		"name":     name,
	})
	require.Equal(t, http.StatusOK, upRes.Status, string(upRes.Body))
	require.NotEmpty(t, c.bearerTok)

	// [3] getSession emits set-auth-jwt header and verifies with JWK
	sessRes := c.get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, sessRes.Status, string(sessRes.Body))
	require.NotEmpty(t, c.lastJWT, "expected set-auth-jwt header on get-session")
	sessClaims := verifyEdDSA(c.lastJWT)
	require.Equal(t, email, sessClaims["email"])
	require.Equal(t, name, sessClaims["name"])

	// [4] GET /token
	tokRes := c.get(t, "/api/auth/token")
	require.Equal(t, http.StatusOK, tokRes.Status, string(tokRes.Body))
	var tokBody struct {
		Token string `json:"token"`
	}
	tokRes.JSON(t, &tokBody)
	require.NotEmpty(t, tokBody.Token)
	tokClaims := verifyEdDSA(tokBody.Token)
	require.Equal(t, email, tokClaims["email"])

	// [5] POST /sign-jwt and /verify-jwt are server-only in better-auth: not routed over HTTP
	signRes := c.post(t, "/api/auth/sign-jwt", map[string]any{
		"payload": map[string]any{"sub": "custom-subject-456", "role": "superadmin"},
	})
	require.Equal(t, http.StatusNotFound, signRes.Status, string(signRes.Body))
	verRes := c.post(t, "/api/auth/verify-jwt", map[string]any{"token": tokBody.Token})
	require.Equal(t, http.StatusNotFound, verRes.Status, string(verRes.Body))

	// [6] custom claims are signed from Go (auth.api.signJWT) and verify with the JWKS key
	jwtPlug, ok := s.Auth.Plugin(jwtplugin.PluginID).(*jwtplugin.Plugin)
	require.True(t, ok)
	customTok, err := jwtPlug.SignJWT(context.Background(), map[string]any{
		"sub":    "custom-subject-456",
		"role":   "superadmin",
		"scopes": []string{"read", "write", "delete"},
	}, nil)
	require.NoError(t, err)
	customClaims := verifyEdDSA(customTok)
	require.Equal(t, "custom-subject-456", customClaims["sub"])
	require.Equal(t, "superadmin", customClaims["role"])

	// [7] auth.api.verifyJWT from Go: valid token returns the payload, an invalid one an error
	payload, err := jwtPlug.VerifyJWT(context.Background(), customTok, "")
	require.NoError(t, err)
	require.Equal(t, "custom-subject-456", payload["sub"])
	_, err = jwtPlug.VerifyJWT(context.Background(), "bad.jwt.token", "")
	require.Error(t, err)
}
