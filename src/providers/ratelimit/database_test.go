package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/memory"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// TestDatabaseStorage checks better-auth's database storage semantics on the rateLimit model.
func TestDatabaseStorage(t *testing.T) {
	ctx := context.Background()
	reg := schema.MustBuild(schema.Options{RateLimit: true})
	a := memory.New(reg)
	s := ratelimit.NewDatabaseStorage(a)

	// Step 1: no record yet
	rec, err := s.Get(ctx, "1.2.3.4|/sign-in/email")
	require.NoError(t, err)
	require.Nil(t, rec)

	// Step 2: insert, then update by key
	now := time.Now().UnixMilli()
	require.NoError(t, s.Set(ctx, "1.2.3.4|/sign-in/email", ratelimit.Record{Key: "1.2.3.4|/sign-in/email", Count: 1, LastRequest: now}, false, time.Second))
	require.NoError(t, s.Set(ctx, "1.2.3.4|/sign-in/email", ratelimit.Record{Key: "1.2.3.4|/sign-in/email", Count: 2, LastRequest: now + 5}, true, time.Second))
	rec, err = s.Get(ctx, "1.2.3.4|/sign-in/email")
	require.NoError(t, err)
	require.Equal(t, &ratelimit.Record{Key: "1.2.3.4|/sign-in/email", Count: 2, LastRequest: now + 5}, rec)

	// Step 3: an insert racing another one for the same key updates instead of failing
	require.NoError(t, s.Set(ctx, "1.2.3.4|/sign-in/email", ratelimit.Record{Count: 7, LastRequest: now + 9}, false, time.Second))
	n, err := a.Count(ctx, "rateLimit", []adapter.Where{{Field: "key", Value: "1.2.3.4|/sign-in/email"}})
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	rec, err = s.Get(ctx, "1.2.3.4|/sign-in/email")
	require.NoError(t, err)
	require.Equal(t, 7, rec.Count)

	// Step 4: a registry without the model reports errors (the limiter logs them)
	plain := ratelimit.NewDatabaseStorage(memory.New(schema.MustBuild(schema.Options{})))
	_, err = plain.Get(ctx, "k")
	require.ErrorIs(t, err, adapter.ErrUnknownModel)
}
