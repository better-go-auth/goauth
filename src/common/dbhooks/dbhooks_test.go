package dbhooks

import (
	"context"
	"errors"
	"testing"

	"github.com/better-go-auth/goauth/src/models"
)

// fakeTx is a transaction manager that records whether fn succeeded (rollback on error).
type fakeTx struct{ calls int }

func (f *fakeTx) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	f.calls++
	return fn(ctx)
}

func TestRunOrderAndModify(t *testing.T) {
	ctx := context.Background()
	var order []string
	set := NewSet()
	// Step 1: two sources; the first changes the record, the second sees the change
	set.Add("plugin:a", Hooks{User: ModelHooks[models.User]{Create: CreateHooks[models.User]{
		Before: func(_ context.Context, u *models.User) error {
			order = append(order, "a")
			u.Name = "from-a"
			return nil
		},
	}}})
	set.Add("user", Hooks{User: ModelHooks[models.User]{Create: CreateHooks[models.User]{
		Before: func(_ context.Context, u *models.User) error {
			order = append(order, "user:"+u.Name)
			return nil
		},
		After: func(_ context.Context, u *models.User) error {
			order = append(order, "after")
			return nil
		},
	}}})
	u := &models.User{}
	if err := RunCreateBefore(ctx, set, User, u); err != nil {
		t.Fatal(err)
	}
	if err := RunCreateAfter(ctx, set, User, u); err != nil {
		t.Fatal(err)
	}
	if want := []string{"a", "user:from-a", "after"}; len(order) != 3 || order[0] != want[0] || order[1] != want[1] || order[2] != want[2] {
		t.Fatalf("order %v", order)
	}
	// Step 2: other models have no hooks
	if Has(set, Session) || !Has(set, User) {
		t.Fatal("Has")
	}
	if err := RunCreateBefore(ctx, set, Session, &models.Session{}); err != nil {
		t.Fatal(err)
	}
}

func TestCancelAndErrorStopTheChain(t *testing.T) {
	ctx := context.Background()
	reached := false
	set := NewSet()
	set.Add("a", Hooks{Account: ModelHooks[models.Account]{Delete: DeleteHooks[models.Account]{
		Before: func(context.Context, *models.Account) error { return ErrCancel },
	}}})
	set.Add("b", Hooks{Account: ModelHooks[models.Account]{Delete: DeleteHooks[models.Account]{
		Before: func(context.Context, *models.Account) error { reached = true; return nil },
	}}})
	err := RunDeleteBefore(ctx, set, Account, &models.Account{})
	if !IsCancel(err) || reached {
		t.Fatalf("cancel must stop the chain: %v %v", err, reached)
	}
	boom := errors.New("boom")
	set2 := NewSet()
	set2.Add("a", Hooks{Verification: ModelHooks[models.Verification]{Update: UpdateHooks[models.Verification]{
		Before: func(_ context.Context, data map[string]any) error { data["value"] = "x"; return boom },
	}}})
	data := map[string]any{}
	if err := RunUpdateBefore(ctx, set2, Verification, data); !errors.Is(err, boom) || data["value"] != "x" {
		t.Fatalf("error: %v %v", err, data)
	}
}

func TestAfterHooksWaitForTheCommit(t *testing.T) {
	ctx := context.Background()
	ran := 0
	set := NewSet()
	set.Add("user", Hooks{Session: ModelHooks[models.Session]{Create: CreateHooks[models.Session]{
		After: func(ctx context.Context, _ *models.Session) error {
			// after hooks run outside the transaction: no queue in their context
			if _, queued := ctx.Value(afterQueueKey{}).(*afterQueue); queued {
				t.Error("after hook must run outside the transaction")
			}
			ran++
			return nil
		},
	}}})
	tx := WrapTx(&fakeTx{})

	// Step 1: committed transaction: the hook runs once, after fn returned
	err := tx.Transaction(ctx, func(ctx context.Context) error {
		if err := RunCreateAfter(ctx, set, Session, &models.Session{}); err != nil {
			return err
		}
		// nested transactions don't flush early
		return tx.Transaction(ctx, func(ctx context.Context) error {
			if ran != 0 {
				t.Error("after hook ran inside the transaction")
			}
			return RunCreateAfter(ctx, set, Session, &models.Session{})
		})
	})
	if err != nil || ran != 2 {
		t.Fatalf("commit: ran %d, err %v", ran, err)
	}
	// Step 2: rolled back transaction: queued hooks are dropped
	ran = 0
	boom := errors.New("rollback")
	err = tx.Transaction(ctx, func(ctx context.Context) error {
		_ = RunCreateAfter(ctx, set, Session, &models.Session{})
		return boom
	})
	if !errors.Is(err, boom) || ran != 0 {
		t.Fatalf("rollback: ran %d, err %v", ran, err)
	}
	// Step 3: an after hook error is returned after the commit
	set.Add("failing", Hooks{Session: ModelHooks[models.Session]{Create: CreateHooks[models.Session]{
		After: func(context.Context, *models.Session) error { return boom },
	}}})
	err = tx.Transaction(ctx, func(ctx context.Context) error {
		return RunCreateAfter(ctx, set, Session, &models.Session{})
	})
	if !errors.Is(err, boom) {
		t.Fatalf("after error: %v", err)
	}
	// Step 4: WrapTx is idempotent and keeps nil
	if WrapTx(tx) != tx || WrapTx(nil) != nil {
		t.Fatal("WrapTx")
	}
}

func TestTarget(t *testing.T) {
	ctx := WithTarget(context.Background(), "u1")
	if Target(ctx) != "u1" || Target(context.Background()) != "" {
		t.Fatal("Target")
	}
	var nilSet *Set
	nilSet.Add("x", Hooks{})
	if len(nilSet.Sources()) != 0 {
		t.Fatal("nil set")
	}
}
