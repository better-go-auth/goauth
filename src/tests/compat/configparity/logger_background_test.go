package configparity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	authlog "github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/config"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// logSink collects log messages from AuthConfig.Logger.Log.
type logSink struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logSink) log(level authlog.Level, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, fmt.Sprintf("%s %s %v", level, msg, args))
}

func (l *logSink) contains(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.msgs {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// TestLoggerOptions: SetupGoAuth installs the logger built from AuthConfig.Logger for goauth's packages;
// Level filters, Disabled silences, Log receives the messages.
func TestLoggerOptions(t *testing.T) {
	t.Cleanup(func() { authlog.SetDefault(nil) })
	boom := func(c *config.AuthConfig) {
		c.Hooks.Before = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			if c.Path == "/ok" {
				return nil, errors.New("boom")
			}
			return nil, nil
		}
	}

	t.Run("custom log function and level", func(t *testing.T) {
		sink := &logSink{}
		s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
			boom(c)
			c.Logger = authlog.Options{Level: authlog.LevelDebug, Log: sink.log}
		}))
		if s.Auth.Logger().Level() != authlog.LevelDebug {
			t.Fatalf("level = %s", s.Auth.Logger().Level())
		}
		// an internal error is logged at error level through the custom function
		s.Get(t, "/api/auth/ok")
		if !sink.contains("error goauth: internal error") || !sink.contains("boom") {
			t.Fatalf("messages = %v", sink.msgs)
		}
		// debug messages of goauth packages go through the installed logger
		authlog.Debug("debug probe")
		authlog.Default().Success("success probe")
		if !sink.contains("debug debug probe") || !sink.contains("info success probe") {
			t.Fatalf("messages = %v", sink.msgs)
		}
	})
	t.Run("default level warn drops debug and info", func(t *testing.T) {
		sink := &logSink{}
		compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) { c.Logger.Log = sink.log }))
		authlog.Debug("hidden debug")
		authlog.Info("hidden info")
		authlog.Warn("visible warn")
		if sink.contains("hidden") || !sink.contains("warn visible warn") {
			t.Fatalf("messages = %v", sink.msgs)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		sink := &logSink{}
		s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
			boom(c)
			c.Logger = authlog.Options{Disabled: true, Log: sink.log}
		}))
		s.Get(t, "/api/auth/ok")
		authlog.Error("not published")
		if len(sink.msgs) != 0 {
			t.Fatalf("disabled logger published %v", sink.msgs)
		}
	})
}

// taskQueue is an Advanced.BackgroundTasks.Handler that keeps tasks until run is called.
type taskQueue struct {
	mu    sync.Mutex
	tasks []func()
}

func (q *taskQueue) handler(task func()) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.tasks = append(q.tasks, task)
}

func (q *taskQueue) run() int {
	q.mu.Lock()
	tasks := q.tasks
	q.tasks = nil
	q.mu.Unlock()
	for _, task := range tasks {
		task()
	}
	return len(tasks)
}

// TestBackgroundTasks: with Advanced.BackgroundTasks.Handler senders run after the response through the
// handler (with a context that outlives the request) and their errors are only logged.
func TestBackgroundTasks(t *testing.T) {
	t.Cleanup(func() { authlog.SetDefault(nil) })
	queue := &taskQueue{}
	sink := &logSink{}
	var mu sync.Mutex
	var resetLinks []string
	var ctxErrs []error
	failReset := false
	var otps []string
	s := compattest.NewServer(t,
		compattest.WithPlugin(emailotp.New(emailotpconfig.EmailOTPConfig{
			SendVerificationOTP: func(d emailotpconfig.SendVerificationOTPData, r *http.Request) error {
				mu.Lock()
				defer mu.Unlock()
				otps = append(otps, d.OTP)
				return nil
			},
		})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.Advanced.BackgroundTasks.Handler = queue.handler
			c.Logger.Log = sink.log
			c.EmailAndPassword.SendResetPassword = func(d config.ResetPasswordData, r *http.Request) error {
				mu.Lock()
				defer mu.Unlock()
				if r != nil {
					ctxErrs = append(ctxErrs, r.Context().Err())
				}
				if failReset {
					return errors.New("smtp down")
				}
				resetLinks = append(resetLinks, d.URL)
				return nil
			}
		}))
	signUp(t, s, "bg@example.com")

	// Step 1: the endpoint answers before the e-mail is sent
	if res := s.Post(t, "/api/auth/request-password-reset", map[string]any{"email": "bg@example.com"}); res.Status != http.StatusOK {
		t.Fatalf("request-password-reset: %d %s", res.Status, res.Body)
	}
	if len(resetLinks) != 0 {
		t.Fatal("sender ran before the background handler")
	}
	// Step 2: the queued task sends it, with a context that is not cancelled with the request
	time.Sleep(10 * time.Millisecond)
	if n := queue.run(); n != 1 {
		t.Fatalf("queued tasks = %d", n)
	}
	if len(resetLinks) != 1 || !strings.Contains(resetLinks[0], "/reset-password/") {
		t.Fatalf("reset links = %v", resetLinks)
	}
	for _, err := range ctxErrs {
		if err != nil {
			t.Fatalf("background task got a cancelled context: %v", err)
		}
	}
	// Step 3: a failing background sender does not fail the request; the error is logged
	failReset = true
	if res := s.Post(t, "/api/auth/request-password-reset", map[string]any{"email": "bg@example.com"}); res.Status != http.StatusOK {
		t.Fatalf("request-password-reset with failing sender: %d", res.Status)
	}
	queue.run()
	if !sink.contains("Failed to run background task:") || !sink.contains("smtp down") {
		t.Fatalf("background failure not logged: %v", sink.msgs)
	}
	// Step 4: plugin senders (email-otp) go through the handler too
	if res := s.Post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": "bg@example.com", "type": "sign-in"}); res.Status != http.StatusOK {
		t.Fatalf("send-verification-otp: %d %s", res.Status, res.Body)
	}
	if len(otps) != 0 || queue.run() != 1 || len(otps) != 1 {
		t.Fatalf("email-otp sender not run through the handler (otps=%v)", otps)
	}
}

// TestSendersSynchronousByDefault: without a handler senders run before the response and their errors fail
// the request (goauth's behaviour so far).
func TestSendersSynchronousByDefault(t *testing.T) {
	var sent bool
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.EmailAndPassword.SendResetPassword = func(d config.ResetPasswordData, r *http.Request) error {
			sent = true
			return nil
		}
	}))
	signUp(t, s, "sync@example.com")
	if res := s.Post(t, "/api/auth/request-password-reset", map[string]any{"email": "sync@example.com"}); res.Status != http.StatusOK || !sent {
		t.Fatalf("sync sender: %d sent=%v", res.Status, sent)
	}
	ctx := context.Background()
	cfg := config.AuthConfig{}
	if err := cfg.RunInBackgroundOrAwait(ctx, func(context.Context) error { return errors.New("x") }); err == nil {
		t.Fatal("synchronous task error must be returned")
	}
}
