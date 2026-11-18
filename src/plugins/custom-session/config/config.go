// Package config holds the options of the custom-session plugin (better-auth's customSession(fn, options,
// pluginOptions)).
package config

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/models/dtos"
)

// Session is what the custom-session callback receives: the session and user the core endpoint returned.
type Session struct {
	// Session is the session, decoded from the core response.
	Session dtos.SessionData
	// User is the user, decoded from the core response.
	User dtos.UserResponse
	// Raw is the core response object as decoded JSON ({"session": {...}, "user": {...}}), including the
	// additional and plugin fields the typed structs do not carry.
	Raw map[string]any
	// Request is the incoming HTTP request.
	Request *http.Request
}

// Func is better-auth's customSession callback: it returns the JSON value sent instead of the session
// (usually the session and user plus extra data, e.g. roles). An error fails the request with that error.
type Func func(ctx context.Context, s *Session) (any, error)

// CustomSessionConfig holds the options of the custom-session plugin.
type CustomSessionConfig struct {
	// Fn transforms the GET /get-session response (required).
	Fn Func
	// ShouldMutateListDeviceSessionsEndpoint also runs Fn on every entry of the multi-session plugin's
	// GET /multi-session/list-device-sessions response (better-auth's pluginOptions option, default false).
	ShouldMutateListDeviceSessionsEndpoint bool
}
