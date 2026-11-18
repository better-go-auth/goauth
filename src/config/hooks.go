package config

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/common/logger"
)

// HooksOptions are better-auth's top-level `hooks`: one before and one after hook that run around every
// core and plugin endpoint (check c.Path to act on some endpoints only). Plugins add their own hooks with
// plugins.EndpointHooksProvider; the user hooks run first (see package endpointhooks).
type HooksOptions struct {
	// Before runs before the endpoint; it may change the request, answer instead or fail it.
	Before endpointhooks.BeforeFunc
	// After runs after the endpoint; it sees the response and the new session and may replace the response.
	After endpointhooks.AfterFunc
}

// OnAPIErrorOptions mirror better-auth's `onAPIError`.
type OnAPIErrorOptions struct {
	// Throw re-raises errors instead of answering them: goauth panics with the error (wrap the auth routes in
	// a recovery middleware to handle it), for the same errors OnError receives.
	Throw bool
	// OnError receives the errors better-auth's router passes to onError: unexpected errors (they become
	// 500 INTERNAL_SERVER_ERROR; the error is an *autherr.ReportedError carrying the request ID) and errors
	// raised before the endpoint runs (origin/CSRF check, endpoint before hooks). Errors an endpoint returns
	// on purpose (400 INVALID_EMAIL, 401, ...) are not passed, like better-auth's APIErrors. When set, goauth
	// does not log these errors itself.
	OnError func(err error, r *http.Request)
	// ErrorURL replaces the default error page `<baseURL><basePath>/error`: OAuth callbacks (social,
	// generic-oauth) redirect there on failure, and GET /error redirects there with ?error=CODE.
	ErrorURL string
}

// BackgroundTasks mirror better-auth's `advanced.backgroundTasks`.
type BackgroundTasks struct {
	// Handler runs a task without blocking the response (better-auth's handler(promise)), e.g.
	// `func(task func()) { go task() }` or a worker pool. Senders (verification and reset e-mails, OTPs,
	// magic links, invitations, ...) run through it; their errors are then logged instead of failing the
	// request. nil (default) runs them synchronously and the endpoint fails when the sender fails.
	Handler func(task func())
}

// HTTPRequestOr returns the request stored in ctx (in a background task: the copy bound to the task's
// context), else fallback.
func HTTPRequestOr(ctx context.Context, fallback *http.Request) *http.Request {
	if req := GetHTTPRequest(ctx); req != nil {
		return req
	}
	return fallback
}

// RunInBackgroundOrAwait is better-auth's ctx.context.runInBackgroundOrAwait for a sender callback:
// with Advanced.BackgroundTasks.Handler the task is handed to it (with a context that is not cancelled when
// the response is sent) and errors are logged; without one it runs now and its error is returned.
func (opts *AuthConfig) RunInBackgroundOrAwait(ctx context.Context, task func(ctx context.Context) error) error {
	// Step 1: no handler: run synchronously and let the caller handle the error
	handler := opts.Advanced.BackgroundTasks.Handler
	if handler == nil {
		return task(ctx)
	}
	// Step 2: detach from the request's cancellation (values stay available); the stored *http.Request
	// handed to senders gets the detached context too
	bg := context.WithoutCancel(ctx)
	if req := GetHTTPRequest(ctx); req != nil {
		bg = WithHTTPRequest(bg, req.WithContext(bg))
	}
	// Step 3: hand the task over; a failure is only logged, like better-auth
	handler(func() {
		if err := task(bg); err != nil {
			logger.Error("Failed to run background task:", "err", err)
		}
	})
	return nil
}
