package humaadapter

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

// NewSessionHooks is the old name of ResponseHooks.
//
// Deprecated: use EndpointHooks.
func NewSessionHooks(conf config.AuthConfig, hooks plugins.HookRegistry, cm *cookies.Manager) func(huma.Context, func(huma.Context)) {
	return ResponseHooks(conf, hooks, cm)
}

// ResponseHooks runs goauth's built-in after hooks (OnAfterSignIn interceptors, OnNewSession and OnResponse
// hooks) without user or plugin endpoint hooks. SetupGoAuth now installs EndpointHooks, which runs these
// hooks together with AuthConfig.Hooks and the plugins' endpoint hooks.
//
// Deprecated: use EndpointHooks.
func ResponseHooks(conf config.AuthConfig, hooks plugins.HookRegistry, cm *cookies.Manager) func(huma.Context, func(huma.Context)) {
	return EndpointHooks(conf, hooks, cm, nil)
}

// httpRequestOf builds an *http.Request from the current huma.Context headers (like RequestContext).
func httpRequestOf(ctx huma.Context) *http.Request {
	u := ctx.URL()
	req := &http.Request{Method: ctx.Method(), URL: &u, Host: ctx.Host(), RemoteAddr: ctx.RemoteAddr(), Header: http.Header{}}
	ctx.EachHeader(func(name, value string) { req.Header.Add(name, value) })
	return req.WithContext(ctx.Context())
}
