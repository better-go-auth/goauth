package memory_test

import (
	"testing"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/adaptertest"
	"github.com/better-go-auth/goauth/src/adapter/memory"
	"github.com/better-go-auth/goauth/src/schema"
)

func TestContract(t *testing.T) {
	adaptertest.Run(t, func(t *testing.T, reg *schema.Registry) adapter.Adapter {
		return memory.New(reg)
	}, adaptertest.Config{})
}
