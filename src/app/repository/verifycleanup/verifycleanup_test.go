package verifycleanup_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/better-go-auth/goauth/src/app/repository/memory"
	"github.com/better-go-auth/goauth/src/app/repository/verifycleanup"
	"github.com/better-go-auth/goauth/src/models"
)

func TestFindPurgesExpiredVerifications(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	repos := verifycleanup.Wrap(base)
	require.Same(t, repos, verifycleanup.Wrap(repos), "wrapping twice is a no-op")

	// Step 1: one live and two expired rows
	_, err := base.UpsertVerificationValue(ctx, &models.Verification{Identifier: "live", Value: "a", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	_, err = base.UpsertVerificationValue(ctx, &models.Verification{Identifier: "old-1", Value: "b", ExpiresAt: time.Now().Add(-time.Minute)})
	require.NoError(t, err)
	_, err = base.UpsertVerificationValue(ctx, &models.Verification{Identifier: "old-2", Value: "c", ExpiresAt: time.Now().Add(-time.Minute)})
	require.NoError(t, err)

	// Step 2: reading an expired row still returns it, so callers can answer "expired"
	got, err := repos.FindVerificationValue(ctx, "old-1")
	require.NoError(t, err)
	require.True(t, got.IsExpired())

	// Step 3: the read purged every expired row and kept the live one
	_, err = base.FindVerificationValue(ctx, "old-1")
	require.Error(t, err)
	_, err = base.FindVerificationValue(ctx, "old-2")
	require.Error(t, err)
	_, err = base.FindVerificationValue(ctx, "live")
	require.NoError(t, err)
}
