package hookedrepo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/hookedrepo"
	"github.com/better-go-auth/goauth/src/app/repository/memory"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/dbhooks"
	"github.com/better-go-auth/goauth/src/models"
)

// setup returns memory repositories wrapped with hooks.
func setup(t *testing.T, h dbhooks.Hooks) (*hookedrepo.Repos, *memory.Repos) {
	t.Helper()
	base := memory.New()
	set := dbhooks.NewSet()
	set.Add("test", h)
	return hookedrepo.Wrap(base, set).(*hookedrepo.Repos), base
}

func newUser(email string) *models.User {
	return &models.User{Base: models.Base{ID: "id-" + email}, UserDto: models.UserDto{Email: email, Name: "N"}}
}

func TestUserCreateHooks(t *testing.T) {
	ctx := context.Background()
	var after *models.User
	repos, base := setup(t, dbhooks.Hooks{User: dbhooks.ModelHooks[models.User]{Create: dbhooks.CreateHooks[models.User]{
		Before: func(_ context.Context, u *models.User) error {
			switch u.Email {
			case "cancel@x.io":
				return dbhooks.ErrCancel
			case "fail@x.io":
				return autherr.ErrForbidden.WithMessage("no")
			}
			u.Name = "changed"
			u.SetExtra("plan", "pro")
			return nil
		},
		After: func(_ context.Context, u *models.User) error { after = u; return nil },
	}}})

	// Step 1: the before hook changes the stored record; the after hook sees it
	created, err := repos.CreateUser(ctx, newUser("a@x.io"))
	if err != nil || created.Name != "changed" || after == nil || after.Name != "changed" {
		t.Fatalf("create: %+v %v", created, err)
	}
	stored, _ := base.FindUserByEmail(ctx, "a@x.io")
	if stored == nil || stored.Name != "changed" {
		t.Fatalf("stored %+v", stored)
	}
	// Step 2: cancel → nothing stored, ErrCancel wrapped in HookError
	after = nil
	_, err = repos.CreateUser(ctx, newUser("cancel@x.io"))
	if !dbhooks.IsCancel(err) || !hookedrepo.IsHookError(err) || after != nil {
		t.Fatalf("cancel: %v", err)
	}
	if u, _ := base.FindUserByEmail(ctx, "cancel@x.io"); u != nil {
		t.Fatal("a cancelled user must not be stored")
	}
	// Step 3: a hook's AuthError reaches the caller
	_, err = repos.CreateUser(ctx, newUser("fail@x.io"))
	if ae := autherr.AsAuthError(err); ae == nil || ae.Message != "no" || !hookedrepo.IsHookError(err) {
		t.Fatalf("hook error: %v", err)
	}
}

func TestUserUpdateHooks(t *testing.T) {
	ctx := context.Background()
	var seen map[string]any
	var target string
	repos, base := setup(t, dbhooks.Hooks{User: dbhooks.ModelHooks[models.User]{Update: dbhooks.UpdateHooks[models.User]{
		Before: func(ctx context.Context, data map[string]any) error {
			if data["name"] == "cancel" {
				return dbhooks.ErrCancel
			}
			seen = map[string]any{}
			for k, v := range data {
				seen[k] = v
			}
			target = dbhooks.Target(ctx)
			data["bio"] = "set by hook"
			return nil
		},
	}}})
	u, _ := base.CreateUser(ctx, newUser("b@x.io"))

	// Step 1: Go field names are presented by field name, hook changes are applied
	updated, err := repos.UpdateUser(ctx, u.ID, map[string]any{"EmailVerified": true, "name": "Bob"})
	if err != nil || !updated.EmailVerified || updated.Name != "Bob" || updated.Bio == nil || *updated.Bio != "set by hook" {
		t.Fatalf("update: %+v %v", updated, err)
	}
	if seen["emailVerified"] != true || seen["name"] != "Bob" || target != u.ID {
		t.Fatalf("hook saw %v (target %q)", seen, target)
	}
	// Step 2: cancel returns the stored user unchanged
	same, err := repos.UpdateUser(ctx, u.ID, map[string]any{"name": "cancel"})
	if err != nil || same.Name != "Bob" {
		t.Fatalf("cancel: %+v %v", same, err)
	}
	// Step 3: goauth's bookkeeping columns don't run hooks
	seen = nil
	if _, err := repos.UpdateUser(ctx, u.ID, map[string]any{"LastLoginAt": time.Now()}); err != nil || seen != nil {
		t.Fatalf("bookkeeping: %v %v", seen, err)
	}
}

func TestDeleteHooks(t *testing.T) {
	ctx := context.Background()
	var deleted []string
	cancelAccounts := false
	repos, base := setup(t, dbhooks.Hooks{
		User: dbhooks.ModelHooks[models.User]{Delete: dbhooks.DeleteHooks[models.User]{
			Before: func(_ context.Context, u *models.User) error {
				deleted = append(deleted, "before:user:"+u.Email)
				return nil
			},
			After: func(_ context.Context, u *models.User) error {
				deleted = append(deleted, "after:user:"+u.Email)
				return nil
			},
		}},
		Account: dbhooks.ModelHooks[models.Account]{Delete: dbhooks.DeleteHooks[models.Account]{
			Before: func(_ context.Context, a *models.Account) error {
				if cancelAccounts {
					return dbhooks.ErrCancel
				}
				deleted = append(deleted, "account:"+a.ID)
				return nil
			},
		}},
		Session: dbhooks.ModelHooks[models.Session]{Delete: dbhooks.DeleteHooks[models.Session]{
			After: func(_ context.Context, s *models.Session) error {
				deleted = append(deleted, "session:"+s.Token)
				return nil
			},
		}},
	})
	u, _ := base.CreateUser(ctx, newUser("c@x.io"))
	_, _ = base.CreateAccount(ctx, &models.Account{Base: models.Base{ID: "acc1"}, UserID: u.ID, ProviderID: "credential", AccountID: u.ID})
	_, _ = base.CreateSession(ctx, &models.Session{Base: models.Base{ID: "s1"}, Token: "tok1", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)})

	// Step 1: a cancelled account delete keeps the accounts
	cancelAccounts = true
	if err := repos.DeleteAccounts(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := base.FindAccounts(ctx, u.ID); len(list) != 1 {
		t.Fatalf("accounts must survive a cancel: %v", list)
	}
	// Step 2: DeleteAccount by id finds the record for its hooks
	cancelAccounts = false
	if err := repos.DeleteAccount(ctx, "acc1"); err != nil {
		t.Fatal(err)
	}
	// Step 3: sessions and the user
	if err := repos.DeleteUserSessions(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := repos.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	want := []string{"account:acc1", "session:tok1", "before:user:c@x.io", "after:user:c@x.io"}
	if len(deleted) != len(want) {
		t.Fatalf("hooks %v, want %v", deleted, want)
	}
	for i := range want {
		if deleted[i] != want[i] {
			t.Fatalf("hooks %v, want %v", deleted, want)
		}
	}
}

func TestVerificationHooks(t *testing.T) {
	ctx := context.Background()
	var events []string
	cancelConsume := false
	repos, _ := setup(t, dbhooks.Hooks{Verification: dbhooks.ModelHooks[models.Verification]{
		Create: dbhooks.CreateHooks[models.Verification]{After: func(_ context.Context, v *models.Verification) error {
			events = append(events, "create:"+v.Identifier)
			return nil
		}},
		Update: dbhooks.UpdateHooks[models.Verification]{Before: func(_ context.Context, data map[string]any) error {
			data["value"] = data["value"].(string) + "!"
			return nil
		}},
		Delete: dbhooks.DeleteHooks[models.Verification]{Before: func(_ context.Context, v *models.Verification) error {
			if cancelConsume {
				return dbhooks.ErrCancel
			}
			events = append(events, "delete:"+v.Value)
			return nil
		}},
	}})
	v, err := repos.UpsertVerificationValue(ctx, &models.Verification{Base: models.Base{ID: "v1"}, Identifier: "otp:a", Value: "123", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Step 1: the update hook changes the new value of the compare-and-swap
	if ok, err := repos.UpdateVerificationValue(ctx, v.ID, "123", "456"); !ok || err != nil {
		t.Fatalf("cas: %v %v", ok, err)
	}
	// Step 2: a cancelled consume consumes nothing and reports not found
	cancelConsume = true
	if _, err := repos.ConsumeVerificationValue(ctx, "otp:a"); err == nil {
		t.Fatal("cancelled consume must fail")
	}
	cancelConsume = false
	got, err := repos.ConsumeVerificationValue(ctx, "otp:a")
	if err != nil || got.Value != "456!" {
		t.Fatalf("consume: %+v %v", got, err)
	}
	if len(events) != 2 || events[0] != "create:otp:a" || events[1] != "delete:456!" {
		t.Fatalf("events %v", events)
	}
}

func TestWrapNil(t *testing.T) {
	base := memory.New()
	if hookedrepo.Wrap(base, nil) != base {
		t.Fatal("nil set must not wrap")
	}
	if hookedrepo.Wrap(nil, dbhooks.NewSet()) != nil {
		t.Fatal("nil repos")
	}
	if hookedrepo.IsHookError(errors.New("x")) {
		t.Fatal("IsHookError")
	}
}
