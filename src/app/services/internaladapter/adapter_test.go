package internaladapter_test

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/hookedrepo"
	"github.com/better-go-auth/goauth/src/app/repository/memory"
	"github.com/better-go-auth/goauth/src/app/services/internaladapter"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/dbhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// newAdapter builds the internal adapter over memory repositories with a registry declaring "plan" and
// "birthday" and the admin plugin's columns.
func newAdapter(t *testing.T, soft bool, h dbhooks.Hooks) (*internaladapter.Adapter, *memory.Repos, plugins.HookRegistry) {
	t.Helper()
	reg := schema.MustBuild(schema.Options{InstalledPlugins: []string{"admin"}, Models: map[string]schema.ModelOptions{
		schema.ModelUser: {AdditionalFields: map[string]schema.Field{"plan": {Type: schema.String}, "birthday": {Type: schema.Date}}},
	}})
	base := memory.New()
	set := dbhooks.NewSet()
	hooks := plugins.NewHookRegistry()
	set.Add("goauth:hooks", internaladapter.TypedHooks(hooks))
	set.Add("user", h)
	repos := hookedrepo.Wrap(base, set)
	cfg := config.Session{}
	mgr := sessionsvc.NewManager(cfg, repos, repos, nil, hooks, sessionsvc.WithRegistry(reg), sessionsvc.WithDatabaseHooks(set))
	return internaladapter.New(internaladapter.Deps{Repos: repos, Sessions: mgr, Schema: reg, Hooks: hooks, SoftDelete: soft}), base, hooks
}

func TestCreateUserFillsDefaultsAndRunsTypedHooks(t *testing.T) {
	ctx := context.Background()
	a, base, hooks := newAdapter(t, false, dbhooks.Hooks{})
	typed := false
	hooks.OnBeforeUserCreate(func(context.Context, *models.User) error { typed = true; return nil })
	// Step 1: id, timestamps and the lower-cased email are filled; the typed hook runs as a database hook
	u, err := a.CreateUser(ctx, &models.User{UserDto: models.UserDto{Email: " MiXed@Example.COM ", Name: "M"}})
	require.NoError(t, err)
	require.True(t, typed)
	require.NotEmpty(t, u.ID)
	require.False(t, u.CreatedAt.IsZero())
	require.Equal(t, "mixed@example.com", u.Email)
	stored, err := base.FindUserByID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, u.Email, stored.Email)
}

func TestSetUserFields(t *testing.T) {
	a, _, _ := newAdapter(t, false, dbhooks.Hooks{})
	u := &models.User{}
	// Step 1: struct fields get their Go type, runtime fields go to Extra, unknown keys are ignored
	err := a.SetUserFields(u, map[string]any{"plan": "pro", "birthday": "2000-01-02", "banned": true, "image": "i.png", "nope": 1,
		// a field of a plugin that isn't installed is not a user field
		"twoFactorEnabled": true})
	require.NoError(t, err)
	require.True(t, u.Banned)
	require.Equal(t, "i.png", *u.Image)
	require.Equal(t, "pro", u.Extra["plan"])
	require.Equal(t, time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC), u.Extra["birthday"])
	require.NotContains(t, u.Extra, "nope")
	require.False(t, u.TwoFactorEnabled)
	// Step 2: a value that doesn't fit is a validation error
	err = a.SetUserFields(u, map[string]any{"banned": "yes"})
	require.Equal(t, "VALIDATION_ERROR", string(autherr.AsAuthError(err).Code))
}

func TestUpdateUserNormalizesAndDropsUnknownKeys(t *testing.T) {
	ctx := context.Background()
	var seen map[string]any
	a, base, _ := newAdapter(t, false, dbhooks.Hooks{User: dbhooks.ModelHooks[models.User]{Update: dbhooks.UpdateHooks[models.User]{
		Before: func(_ context.Context, data map[string]any) error { seen = data; return nil },
	}}})
	u, err := a.CreateUser(ctx, &models.User{UserDto: models.UserDto{Email: "u@example.com", Name: "U"}})
	require.NoError(t, err)
	updated, err := a.UpdateUser(ctx, u.ID, map[string]any{"Email": "NEW@Example.com", "plan": "team", "unknownKey": 1, "twoFactorEnabled": true})
	require.NoError(t, err)
	require.Equal(t, "new@example.com", updated.Email)
	require.Equal(t, "team", updated.Extra["plan"])
	require.Equal(t, map[string]any{"email": "new@example.com", "plan": "team"}, seen)
	stored, _ := base.FindUserByID(ctx, u.ID)
	require.Equal(t, "team", stored.Extra["plan"])
}

func TestDeleteUserRunsTheFullSequence(t *testing.T) {
	ctx := context.Background()
	for _, soft := range []bool{false, true} {
		var events []string
		a, base, hooks := newAdapter(t, soft, dbhooks.Hooks{User: dbhooks.ModelHooks[models.User]{Delete: dbhooks.DeleteHooks[models.User]{
			After: func(_ context.Context, u *models.User) error { events = append(events, "deleted:"+u.Email); return nil },
		}}})
		hooks.OnUserDeleted(func(_ context.Context, id string) error { events = append(events, "plugin-rows"); return nil })
		u, err := a.CreateUser(ctx, &models.User{UserDto: models.UserDto{Email: "d@example.com", Name: "D"}})
		require.NoError(t, err)
		_, err = a.LinkAccount(ctx, &models.Account{UserID: u.ID, AccountID: u.ID, ProviderID: models.ProvCredential})
		require.NoError(t, err)
		_, err = a.CreateSession(ctx, u, sessionsvc.Meta{}, sessionsvc.CreateOptions{})
		require.NoError(t, err)

		require.NoError(t, a.DeleteUser(ctx, u.ID))
		require.ElementsMatch(t, []string{"plugin-rows", "deleted:d@example.com"}, events)
		_, err = base.FindUserByID(ctx, u.ID)
		require.Error(t, err)
		accounts, _ := base.FindAccounts(ctx, u.ID)
		require.Empty(t, accounts)
		sessions, _ := base.ListSessions(ctx, u.ID)
		require.Empty(t, sessions)
	}
}

func TestCreateUserCancel(t *testing.T) {
	a, _, _ := newAdapter(t, false, dbhooks.Hooks{User: dbhooks.ModelHooks[models.User]{Create: dbhooks.CreateHooks[models.User]{
		Before: func(context.Context, *models.User) error { return dbhooks.ErrCancel },
	}}})
	_, err := a.CreateUser(context.Background(), &models.User{UserDto: models.UserDto{Email: "c@example.com"}})
	require.True(t, a.IsCancelled(err))
}
