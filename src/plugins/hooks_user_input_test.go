package plugins_test

import (
	"context"
	"errors"
	"testing"

	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/stretchr/testify/require"
)

func TestHookRegistry_UserInput(t *testing.T) {
	registry := plugins.NewHookRegistry()
	ctx := context.Background()

	// Step 1: no hooks is a no-op
	require.NoError(t, registry.TriggerUserInput(ctx, &plugins.UserInputEvent{Path: plugins.UserInputUpdateUser}))

	// Step 2: hooks run in order and may write the update; the first error stops the chain
	var order []string
	registry.OnUserInput(func(_ context.Context, ev *plugins.UserInputEvent) error {
		order = append(order, "first")
		ev.Update["Username"] = ev.Body["username"]
		return nil
	})
	boom := errors.New("boom")
	registry.OnUserInput(func(context.Context, *plugins.UserInputEvent) error {
		order = append(order, "second")
		return boom
	})
	registry.OnUserInput(func(context.Context, *plugins.UserInputEvent) error {
		order = append(order, "third")
		return nil
	})
	ev := &plugins.UserInputEvent{Path: plugins.UserInputUpdateUser, Body: map[string]any{"username": "alice"}, Update: map[string]any{}}
	require.ErrorIs(t, registry.TriggerUserInput(ctx, ev), boom)
	require.Equal(t, []string{"first", "second"}, order)
	require.Equal(t, "alice", ev.Update["Username"])
}

func TestHookRegistry_NewSession(t *testing.T) {
	registry := plugins.NewHookRegistry()
	ctx := context.Background()

	// Step 1: nothing registered
	require.False(t, registry.HasNewSessionHooks())
	require.NoError(t, registry.TriggerNewSession(ctx, plugins.NewSessionEvent{}))

	// Step 2: hooks see the event; an error is returned unchanged
	var seen string
	registry.OnNewSession(func(_ context.Context, ev plugins.NewSessionEvent) error {
		seen = ev.Path + ":" + ev.Session.User.ID
		return nil
	})
	require.True(t, registry.HasNewSessionHooks())
	sw := &dtos.SessionWithUser{User: dtos.UserResponse{ID: "u1"}}
	require.NoError(t, registry.TriggerNewSession(ctx, plugins.NewSessionEvent{Path: "/sign-in/email", Session: sw}))
	require.Equal(t, "/sign-in/email:u1", seen)

	boom := errors.New("boom")
	registry.OnNewSession(func(context.Context, plugins.NewSessionEvent) error { return boom })
	require.ErrorIs(t, registry.TriggerNewSession(ctx, plugins.NewSessionEvent{Path: "/x", Session: sw}), boom)
}
