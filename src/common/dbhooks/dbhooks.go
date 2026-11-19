// Package dbhooks is better-auth's `databaseHooks`: functions that run before and after goauth creates,
// updates or deletes a user, session, account or verification row, whichever endpoint or plugin does it.
//
//	cfg.DatabaseHooks = dbhooks.Hooks{
//		User: dbhooks.ModelHooks[models.User]{
//			Create: dbhooks.CreateHooks[models.User]{
//				Before: func(ctx context.Context, u *models.User) error {
//					if strings.HasSuffix(u.Email, "@blocked.example") {
//						return dbhooks.ErrCancel // better-auth's `return false`
//					}
//					u.SetExtra("plan", "free") // better-auth's `return { data: {...} }`
//					return nil
//				},
//			},
//		},
//	}
//
// A Before hook changes the data in place, cancels the operation with ErrCancel (the endpoint then answers
// like better-auth does when its adapter returns null, e.g. 400 FAILED_TO_CREATE_USER on sign-up) or fails it
// with any other error (an *autherr.AuthError reaches the client unchanged, like a thrown APIError). After
// hooks receive the stored record; inside a goauth transaction they run once it committed.
//
// Hooks run in better-auth's order: plugin hooks first (in plugin order), then AuthConfig.DatabaseHooks.
// ctx carries the HTTP request when there is one (config.GetHTTPRequest), better-auth's endpoint context.
package dbhooks

import (
	"context"
	"errors"
	"sync"

	"github.com/better-go-auth/goauth/src/models"
)

// ErrCancel cancels a create, update or delete from a Before hook (better-auth's `return false`).
var ErrCancel = errors.New("dbhooks: operation cancelled by a database hook")

// IsCancel reports whether err is (or wraps) ErrCancel.
func IsCancel(err error) bool { return errors.Is(err, ErrCancel) }

// CreateHooks run around the insert of a T.
type CreateHooks[T any] struct {
	// Before sees the record about to be inserted and may change it in place, cancel (ErrCancel) or fail.
	Before func(ctx context.Context, data *T) error
	// After sees the inserted record.
	After func(ctx context.Context, data *T) error
}

// UpdateHooks run around an update of a T.
type UpdateHooks[T any] struct {
	// Before sees the changes keyed by field name (better-auth's names, e.g. "emailVerified", additional
	// fields included) and may change the map in place, cancel (ErrCancel) or fail.
	Before func(ctx context.Context, data map[string]any) error
	// After sees the updated record.
	After func(ctx context.Context, data *T) error
}

// DeleteHooks run around the delete of a T.
type DeleteHooks[T any] struct {
	// Before sees the record about to be deleted and may cancel (ErrCancel) or fail.
	Before func(ctx context.Context, data *T) error
	// After sees the deleted record.
	After func(ctx context.Context, data *T) error
}

// ModelHooks are the hooks of one model.
type ModelHooks[T any] struct {
	Create CreateHooks[T]
	Update UpdateHooks[T]
	Delete DeleteHooks[T]
}

// Hooks is better-auth's databaseHooks option: hooks per core model.
type Hooks struct {
	User         ModelHooks[models.User]
	Session      ModelHooks[models.Session]
	Account      ModelHooks[models.Account]
	Verification ModelHooks[models.Verification]
}

// Model selectors for the Run* functions.
var (
	User         = func(h *Hooks) *ModelHooks[models.User] { return &h.User }
	Session      = func(h *Hooks) *ModelHooks[models.Session] { return &h.Session }
	Account      = func(h *Hooks) *ModelHooks[models.Account] { return &h.Account }
	Verification = func(h *Hooks) *ModelHooks[models.Verification] { return &h.Verification }
)

// Source is one set of hooks and where it comes from ("plugin:<id>", "user", ...).
type Source struct {
	Name  string
	Hooks Hooks
}

// Set is the ordered list of hook sources goauth runs. It is safe for concurrent use; Add may be called
// while requests run (plugins add their hooks during setup).
type Set struct {
	mu      sync.RWMutex
	sources []Source
}

// NewSet returns an empty Set.
func NewSet() *Set { return &Set{} }

// Add appends a source; hooks run in the order sources were added.
func (s *Set) Add(name string, h Hooks) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, Source{Name: name, Hooks: h})
}

// Sources returns a copy of the sources in run order.
func (s *Set) Sources() []Source {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Source(nil), s.sources...)
}

// RunCreateBefore runs every create.before hook of model on data, in order; the first error stops.
func RunCreateBefore[T any](ctx context.Context, s *Set, model func(*Hooks) *ModelHooks[T], data *T) error {
	for _, src := range s.Sources() {
		if fn := model(&src.Hooks).Create.Before; fn != nil {
			if err := fn(ctx, data); err != nil {
				return err
			}
		}
	}
	return nil
}

// RunCreateAfter runs (or queues until the transaction commits) every create.after hook of model.
func RunCreateAfter[T any](ctx context.Context, s *Set, model func(*Hooks) *ModelHooks[T], data *T) error {
	for _, src := range s.Sources() {
		if fn := model(&src.Hooks).Create.After; fn != nil {
			if err := runOrQueue(ctx, func(ctx context.Context) error { return fn(ctx, data) }); err != nil {
				return err
			}
		}
	}
	return nil
}

// RunUpdateBefore runs every update.before hook of model on the change set data, in order.
func RunUpdateBefore[T any](ctx context.Context, s *Set, model func(*Hooks) *ModelHooks[T], data map[string]any) error {
	for _, src := range s.Sources() {
		if fn := model(&src.Hooks).Update.Before; fn != nil {
			if err := fn(ctx, data); err != nil {
				return err
			}
		}
	}
	return nil
}

// RunUpdateAfter runs (or queues until the transaction commits) every update.after hook of model.
func RunUpdateAfter[T any](ctx context.Context, s *Set, model func(*Hooks) *ModelHooks[T], data *T) error {
	for _, src := range s.Sources() {
		if fn := model(&src.Hooks).Update.After; fn != nil {
			if err := runOrQueue(ctx, func(ctx context.Context) error { return fn(ctx, data) }); err != nil {
				return err
			}
		}
	}
	return nil
}

// RunDeleteBefore runs every delete.before hook of model on the record about to be deleted.
func RunDeleteBefore[T any](ctx context.Context, s *Set, model func(*Hooks) *ModelHooks[T], data *T) error {
	for _, src := range s.Sources() {
		if fn := model(&src.Hooks).Delete.Before; fn != nil {
			if err := fn(ctx, data); err != nil {
				return err
			}
		}
	}
	return nil
}

// RunDeleteAfter runs (or queues until the transaction commits) every delete.after hook of model.
func RunDeleteAfter[T any](ctx context.Context, s *Set, model func(*Hooks) *ModelHooks[T], data *T) error {
	for _, src := range s.Sources() {
		if fn := model(&src.Hooks).Delete.After; fn != nil {
			if err := runOrQueue(ctx, func(ctx context.Context) error { return fn(ctx, data) }); err != nil {
				return err
			}
		}
	}
	return nil
}

// Has reports whether any source has a hook for model (lets callers skip reading a record for delete hooks).
func Has[T any](s *Set, model func(*Hooks) *ModelHooks[T]) bool {
	for _, src := range s.Sources() {
		m := model(&src.Hooks)
		if m.Create.Before != nil || m.Create.After != nil || m.Update.Before != nil || m.Update.After != nil ||
			m.Delete.Before != nil || m.Delete.After != nil {
			return true
		}
	}
	return false
}

// targetKey carries the id of the record an update or delete applies to.
type targetKey struct{}

// WithTarget returns ctx carrying the id of the record being updated (set by goauth before update hooks run).
func WithTarget(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, targetKey{}, id)
}

// Target returns the id of the record an update hook runs for ("" outside update hooks). better-auth's update
// hooks only get the data; goauth also tells which row it applies to (e.g. to skip the user's own username in
// a uniqueness check).
func Target(ctx context.Context) string {
	id, _ := ctx.Value(targetKey{}).(string)
	return id
}
