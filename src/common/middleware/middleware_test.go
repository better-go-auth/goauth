package middleware_test

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_JWTTokenVerifier(t *testing.T) {
	secret := "test-secret-key-32-chars-long-1234"
	claims := &token.CustomClaims{
		UserID:    "user_1",
		SessionID: "sess_1",
		Role:      "USER",
	}

	tokenStr, err := jwttoken.SignWithExpiry(secret, claims, 15*time.Minute)
	require.NoError(t, err)

	verifier := middleware.NewJWTTokenVerifier(secret)
	verifiedClaims, err := verifier.VerifyToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user_1", verifiedClaims.UserID)
	assert.Equal(t, "sess_1", verifiedClaims.SessionID)
	assert.Equal(t, "USER", verifiedClaims.Role)
}

func TestMiddleware_KeyValRevocationStore(t *testing.T) {
	memStore, err := memory.NewSecondaryStorage()
	require.NoError(t, err)

	revStore := middleware.NewKeyValRevocationStore(memStore)
	ctx := context.Background()

	revoked, err := revStore.IsRevoked(ctx, "session_123")
	require.NoError(t, err)
	assert.False(t, revoked)

	// Revoke session
	err = memStore.Set(ctx, "revoked:session:session_123", true, 10*time.Minute)
	require.NoError(t, err)

	revoked, err = revStore.IsRevoked(ctx, "session_123")
	require.NoError(t, err)
	assert.True(t, revoked)
}
