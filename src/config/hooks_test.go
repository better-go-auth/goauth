package config

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/better-go-auth/goauth/src/common/logger"
)

func TestRunInBackgroundOrAwait(t *testing.T) {
	// Step 1: without a handler the task runs now and its error is returned
	var cfg AuthConfig
	ran := false
	if err := cfg.RunInBackgroundOrAwait(context.Background(), func(context.Context) error { ran = true; return errors.New("x") }); err == nil || !ran {
		t.Fatalf("sync: ran=%v err=%v", ran, err)
	}

	// Step 2: with a handler the task is handed over; the request context may be cancelled meanwhile
	var queued []func()
	cfg.Advanced.BackgroundTasks.Handler = func(task func()) { queued = append(queued, task) }
	t.Cleanup(func() { logger.SetDefault(nil) })
	var logged []string
	logger.SetDefault(logger.New(logger.Options{Log: func(l logger.Level, msg string, args ...any) { logged = append(logged, msg) }}))

	req := httptest.NewRequest("POST", "/x", nil)
	reqCtx, cancel := context.WithCancel(req.Context())
	ctx := WithHTTPRequest(reqCtx, req.WithContext(reqCtx))
	var taskCtxErr, reqCtxErr error
	var gotReq bool
	err := cfg.RunInBackgroundOrAwait(ctx, func(ctx context.Context) error {
		taskCtxErr = ctx.Err()
		r := HTTPRequestOr(ctx, nil)
		gotReq = r != nil
		if r != nil {
			reqCtxErr = r.Context().Err()
		}
		return errors.New("send failed")
	})
	if err != nil || len(queued) != 1 {
		t.Fatalf("background: err=%v queued=%d", err, len(queued))
	}
	cancel() // the response was sent
	queued[0]()
	if taskCtxErr != nil || reqCtxErr != nil || !gotReq {
		t.Fatalf("task context: ctx=%v req=%v gotReq=%v", taskCtxErr, reqCtxErr, gotReq)
	}
	if len(logged) != 1 || logged[0] != "Failed to run background task:" {
		t.Fatalf("logged = %v", logged)
	}
	// Step 3: HTTPRequestOr falls back when the context has no request
	fallback := httptest.NewRequest("GET", "/", nil)
	if HTTPRequestOr(context.Background(), fallback) != fallback {
		t.Fatal("fallback")
	}
}

func TestRateLimitIsEnabled(t *testing.T) {
	t.Setenv("GOAUTH_ENV", "")
	t.Setenv("GO_ENV", "")
	t.Setenv("APP_ENV", "")
	t.Setenv("NODE_ENV", "")
	if (RateLimitOptions{}).IsEnabled() {
		t.Fatal("enabled outside production")
	}
	if !(RateLimitOptions{Enabled: new(true)}).IsEnabled() {
		t.Fatal("explicit true")
	}
	t.Setenv("NODE_ENV", "production")
	if !(RateLimitOptions{}).IsEnabled() || (RateLimitOptions{Enabled: new(false)}).IsEnabled() {
		t.Fatal("production default / explicit false")
	}
}
