package goauth

import (
	"testing"

	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
)

func TestSetDefaultsRevocationCheck(t *testing.T) {
	t.Run("forced on without secondary storage", func(t *testing.T) {
		opts := GoAuthOptions{}
		opts.SetDefaults()
		if !opts.SessionConfig.CheckRevocationInDb {
			t.Fatal("CheckRevocationInDb must default to true without secondary storage")
		}
	})

	t.Run("left as configured with secondary storage", func(t *testing.T) {
		store, err := memory.NewSecondaryStorage()
		if err != nil {
			t.Fatal(err)
		}
		opts := GoAuthOptions{SecondaryStorage: store}
		opts.SetDefaults()
		if opts.SessionConfig.CheckRevocationInDb {
			t.Fatal("CheckRevocationInDb must stay false when secondary storage handles revocation")
		}
	})
}
