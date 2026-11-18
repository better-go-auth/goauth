package verifyidentifier_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/memory"
	"github.com/better-go-auth/goauth/src/app/repository/verifyidentifier"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
)

func TestPlainConfigIsNotWrapped(t *testing.T) {
	base := memory.New()
	if verifyidentifier.Wrap(base, config.VerificationOptions{}) != base {
		t.Fatal("plain storage must return the repositories unchanged")
	}
}

func TestHashedIdentifiersAreStoredHashedAndStillFound(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	repos := verifyidentifier.Wrap(base, config.VerificationOptions{StoreIdentifier: config.StoreIdentifierOption{Mode: config.StoreIdentifierHashed}})
	exp := time.Now().Add(time.Hour)

	// Step 1: the row is written under the hash; the caller's struct keeps the plain identifier
	v := &models.Verification{Identifier: "reset-password:tok", Value: "user-1", ExpiresAt: exp}
	if _, err := repos.UpsertVerificationValue(ctx, v); err != nil {
		t.Fatal(err)
	}
	if v.Identifier != "reset-password:tok" {
		t.Fatalf("caller struct changed: %q", v.Identifier)
	}
	if _, err := base.FindVerificationValue(ctx, "reset-password:tok"); err == nil {
		t.Fatal("the plain identifier must not be stored")
	}
	row, err := base.FindVerificationValue(ctx, config.HashIdentifier("reset-password:tok"))
	if err != nil || row.Value != "user-1" {
		t.Fatalf("hashed row: %+v %v", row, err)
	}
	// Step 2: lookups through the wrapper use the plain identifier
	got, err := repos.FindVerificationValue(ctx, "reset-password:tok")
	if err != nil || got.Value != "user-1" {
		t.Fatalf("find: %+v %v", got, err)
	}
	// Step 3: consume removes it
	if got, err := repos.ConsumeVerificationValue(ctx, "reset-password:tok"); err != nil || got.Value != "user-1" {
		t.Fatalf("consume: %+v %v", got, err)
	}
	if _, err := repos.FindVerificationValue(ctx, "reset-password:tok"); err == nil {
		t.Fatal("consumed row must be gone")
	}
}

func TestPlainRowsWrittenBeforeHashingStillWork(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	exp := time.Now().Add(time.Hour)
	// Step 1: rows written while identifiers were stored plain
	for _, id := range []string{"old-1", "old-2"} {
		if _, err := base.UpsertVerificationValue(ctx, &models.Verification{Identifier: id, Value: "v-" + id, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	repos := verifyidentifier.Wrap(base, config.VerificationOptions{StoreIdentifier: config.StoreIdentifierOption{Mode: config.StoreIdentifierHashed}})
	// Step 2: find and consume fall back to the plain identifier (better-auth's identifiersToTry)
	if got, err := repos.FindVerificationValue(ctx, "old-1"); err != nil || got.Value != "v-old-1" {
		t.Fatalf("find fallback: %+v %v", got, err)
	}
	if got, err := repos.ConsumeVerificationValue(ctx, "old-2"); err != nil || got.Value != "v-old-2" {
		t.Fatalf("consume fallback: %+v %v", got, err)
	}
	// Step 3: a missing identifier is still "not found"
	if _, err := repos.FindVerificationValue(ctx, "missing"); err == nil {
		t.Fatal("missing identifier must fail")
	}
}

func TestCustomHashOverridesAndErrors(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	boom := errors.New("hash failed")
	repos := verifyidentifier.Wrap(base, config.VerificationOptions{
		StoreIdentifierOverrides: map[string]config.StoreIdentifierOption{
			"otp:":  {Hash: func(s string) (string, error) { return "h(" + s + ")", nil }},
			"fail:": {Hash: func(string) (string, error) { return "", boom }},
		},
	})
	exp := time.Now().Add(time.Hour)
	// Step 1: only identifiers matching an override are processed
	for _, id := range []string{"otp:1", "plain:1"} {
		if _, err := repos.UpsertVerificationValue(ctx, &models.Verification{Identifier: id, Value: id, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := base.FindVerificationValue(ctx, "h(otp:1)"); err != nil {
		t.Fatalf("custom hash not applied: %v", err)
	}
	if _, err := base.FindVerificationValue(ctx, "plain:1"); err != nil {
		t.Fatalf("non-matching identifier must stay plain: %v", err)
	}
	// Step 2: delete by identifier targets the processed form
	if err := repos.DeleteVerificationByIdentifier(ctx, "otp:1"); err != nil {
		t.Fatal(err)
	}
	if _, err := base.FindVerificationValue(ctx, "h(otp:1)"); err == nil {
		t.Fatal("delete must remove the hashed row")
	}
	// Step 3: hash errors are returned, nothing is written
	if _, err := repos.UpsertVerificationValue(ctx, &models.Verification{Identifier: "fail:1", Value: "x", ExpiresAt: exp}); !errors.Is(err, boom) {
		t.Fatalf("hash error: %v", err)
	}
	if _, err := repos.FindVerificationValue(ctx, "fail:1"); !errors.Is(err, boom) {
		t.Fatalf("hash error on find: %v", err)
	}
}
