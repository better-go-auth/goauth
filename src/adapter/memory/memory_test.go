package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/adaptertest"
	"github.com/better-go-auth/goauth/src/adapter/memory"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

func TestContract(t *testing.T) {
	adaptertest.Run(t, func(t *testing.T, reg *schema.Registry) adapter.Adapter {
		return memory.New(reg)
	}, adaptertest.Config{})
}

// TestDatabaseGeneratedIDs checks the serial and database id strategies on the memory backend: ids come
// from the backend, references to serial ids are stored as integers and read back as strings.
func TestDatabaseGeneratedIDs(t *testing.T) {
	ctx := context.Background()
	for _, ids := range []schema.IDStrategy{schema.IDSerial, schema.IDDatabase} {
		t.Run(string(ids), func(t *testing.T) {
			reg := schema.MustBuild(schema.Options{IDs: ids})
			a := memory.New(reg, adapter.WithIDGenerator(func() string { panic("ids come from the backend") }))
			// Step 1: two users with backend ids
			u1, err := a.Create(ctx, "user", adapter.Record{"name": "A", "email": "a@example.com"})
			require.NoError(t, err)
			u2, err := a.Create(ctx, "user", adapter.Record{"name": "B", "email": "b@example.com"})
			require.NoError(t, err)
			require.NotEqual(t, u1["id"], u2["id"])
			if ids == schema.IDSerial {
				require.Equal(t, "1", u1["id"])
				require.Equal(t, "2", u2["id"])
			} else {
				require.Len(t, u1["id"], 32)
			}
			// Step 2: a session referencing the second user
			s, err := a.Create(ctx, "session", adapter.Record{"userId": u2["id"], "token": "t", "expiresAt": time.Now(), "updatedAt": time.Now()})
			require.NoError(t, err)
			require.Equal(t, u2["id"], s["userId"])
			n, err := a.Count(ctx, "session", []adapter.Where{{Field: "userId", Value: u2["id"]}})
			require.NoError(t, err)
			require.Equal(t, int64(1), n)
			// Step 3: a unique violation doesn't consume a serial id
			_, err = a.Create(ctx, "user", adapter.Record{"name": "dup", "email": "a@example.com"})
			require.ErrorIs(t, err, adapter.ErrUniqueViolation)
			u3, err := a.Create(ctx, "user", adapter.Record{"name": "C", "email": "c@example.com"})
			require.NoError(t, err)
			if ids == schema.IDSerial {
				require.Equal(t, "3", u3["id"])
				// a serial reference that isn't a number is a value error on write, no match on read
				_, err = a.Create(ctx, "session", adapter.Record{"userId": "abc", "token": "t2", "expiresAt": time.Now(), "updatedAt": time.Now()})
				var ve *adapter.ValueError
				require.ErrorAs(t, err, &ve)
				_, err = a.FindOne(ctx, "user", []adapter.Where{{Field: "id", Value: "abc"}})
				require.ErrorIs(t, err, adapter.ErrNotFound)
			}
		})
	}
}
