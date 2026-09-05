package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/providers/memory"
	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_SetAndGet(t *testing.T) {
	s := memory.New()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key1", "value1", 0))
	val, exists, err := s.Get(ctx, "key1")
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, "value1", val)
}

func TestStore_Exists(t *testing.T) {
	s := memory.New()
	ctx := context.Background()

	exists, err := s.Exists(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, exists)

	require.NoError(t, s.Set(ctx, "active", "data", 0))
	exists, err = s.Exists(ctx, "active")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestStore_Expiry(t *testing.T) {
	s := memory.New()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "temp", "data", 50*time.Millisecond))

	val, exists, err := s.Get(ctx, "temp")
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, "data", val)

	time.Sleep(60 * time.Millisecond)

	val, exists, err = s.Get(ctx, "temp")
	require.NoError(t, err)
	assert.False(t, exists)
	assert.Nil(t, val, "expired entry should return nil")

	exists, err = s.Exists(ctx, "temp")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestStore_GetAndDeleteCtx(t *testing.T) {
	s := memory.New()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "key", "val", 0))
	val, err := s.GetAndDeleteCtx(ctx, "key")
	require.NoError(t, err)
	assert.Equal(t, "val", val)

	// Second call should return nil.
	val, err = s.GetAndDeleteCtx(ctx, "key")
	require.NoError(t, err)
	assert.Nil(t, val)
}

func TestStore_Delete(t *testing.T) {
	s := memory.New()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "k", "v", 0))
	require.NoError(t, s.Delete(ctx, "k"))

	val, exists, err := s.Get(ctx, "k")
	require.NoError(t, err)
	assert.False(t, exists)
	assert.Nil(t, val)
}

func TestStore_Flush(t *testing.T) {
	s := memory.New()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "a", "1", 0))
	require.NoError(t, s.Set(ctx, "b", "2", 0))
	assert.Equal(t, 2, s.Len())

	s.Flush()
	assert.Equal(t, 0, s.Len())
}

func TestStore_MissingKeyReturnsNil(t *testing.T) {
	s := memory.New()
	ctx := context.Background()

	val, exists, err := s.Get(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, exists)
	assert.Nil(t, val)
}

// TestStore_ImplementsKeyValServ verifies that memory.Store satisfies db.KeyValServ.
func TestStore_ImplementsKeyValServ(t *testing.T) {
	var _ db.KeyValServ = memory.New()

	sec, err := memory.NewSecondaryStorage()
	require.NoError(t, err)
	require.NotNil(t, sec)
}
