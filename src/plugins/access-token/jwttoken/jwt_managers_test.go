package jwttoken_test

import (
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/access-token/jwttoken"
	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateAccessToken was the core JWTTokenVerifier test; the verifier moved into the access-token plugin.
func TestValidateAccessToken(t *testing.T) {
	secret := "test-secret-key-32-chars-long-1234"
	claims := &token.CustomClaims{
		UserID:    "user_1",
		SessionID: "sess_1",
		Role:      "USER",
		Type:      token.TypeAccess,
	}

	// Step 1: an access token verifies and keeps its claims
	tokenStr, err := jwttoken.SignWithExpiry(secret, claims, 15*time.Minute)
	require.NoError(t, err)
	verified, err := jwttoken.ValidateAccessToken(tokenStr, secret)
	require.NoError(t, err)
	assert.Equal(t, "user_1", verified.UserID)
	assert.Equal(t, "sess_1", verified.SessionID)
	assert.Equal(t, "USER", verified.Role)

	// Step 2: a refresh token is not accepted as an access token
	claims.Type = token.TypeRefresh
	refreshStr, err := jwttoken.SignWithExpiry(secret, claims, 15*time.Minute)
	require.NoError(t, err)
	_, err = jwttoken.ValidateAccessToken(refreshStr, secret)
	assert.Error(t, err, "a refresh token must not be accepted as an access token")
}
