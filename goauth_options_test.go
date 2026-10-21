package goauth

import (
	"testing"

	"github.com/better-go-auth/goauth/src/providers"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
)

func TestRevocationConfig(t *testing.T) {
	t.Run("forced on without secondary storage", func(t *testing.T) {
		opts := GoAuthOptions{}
		opts.SetDefaults()
		cfg := providers.RevocationConfig{
			CheckRevocation: opts.SecondaryStorage == nil,
		}
		if !cfg.CheckRevocation {
			t.Fatal("CheckRevocation must be true without secondary storage")
		}
	})

	t.Run("left off when secondary storage handles revocation", func(t *testing.T) {
		store, err := memory.NewSecondaryStorage()
		if err != nil {
			t.Fatal(err)
		}
		opts := GoAuthOptions{SecondaryStorage: store}
		opts.SetDefaults()
		cfg := providers.RevocationConfig{
			CheckRevocation: opts.SecondaryStorage == nil,
		}
		if cfg.CheckRevocation {
			t.Fatal("CheckRevocation must stay false when secondary storage handles revocation")
		}
	})
}
