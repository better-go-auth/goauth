package adapter_test

import (
	"errors"
	"testing"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/memory"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

func TestLikePattern(t *testing.T) {
	require.Equal(t, "%a!%b!_c!!%", adapter.LikePattern(adapter.Contains, "a%b_c!"))
	require.Equal(t, "pre!_%", adapter.LikePattern(adapter.StartsWith, "pre_"))
	require.Equal(t, "%!%end", adapter.LikePattern(adapter.EndsWith, "%end"))
}

func TestUniqueError(t *testing.T) {
	cause := errors.New("duplicate")
	err := error(&adapter.UniqueError{Model: "user", Fields: []string{"email"}, Err: cause})
	require.ErrorIs(t, err, adapter.ErrUniqueViolation)
	require.ErrorIs(t, err, cause)
	require.Equal(t, "adapter: unique constraint violated on user (email): duplicate", err.Error())
	require.Equal(t, "adapter: unique constraint violated (a, b)", (&adapter.UniqueError{Columns: []string{"a", "b"}}).Error())
}

func TestAsAndRegistryOf(t *testing.T) {
	reg := schema.MustBuild(schema.Options{})
	a := memory.New(reg)
	// Step 1: the factory exposes its registry and backend
	require.Same(t, reg, adapter.RegistryOf(a))
	_, ok := adapter.As[*memory.Backend](a)
	require.True(t, ok)
	// Step 2: the memory backend has no introspection
	_, ok = adapter.As[adapter.Introspector](a)
	require.False(t, ok)
	require.Equal(t, "memory", a.ID())
}
