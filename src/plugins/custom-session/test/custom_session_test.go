package test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	customsession "github.com/better-go-auth/goauth/src/plugins/custom-session"
	csconfig "github.com/better-go-auth/goauth/src/plugins/custom-session/config"
	multisession "github.com/better-go-auth/goauth/src/plugins/multi-session"
	msconfig "github.com/better-go-auth/goauth/src/plugins/multi-session/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const password = "Password123!"

// rolesFn is the typical better-auth example: add the user's roles next to session and user.
func rolesFn(calls *atomic.Int32) csconfig.Func {
	return func(_ context.Context, s *csconfig.Session) (any, error) {
		calls.Add(1)
		return map[string]any{
			"roles":   []string{"editor"},
			"user":    map[string]any{"id": s.User.ID, "email": s.User.Email, "newField": "custom"},
			"session": s.Session,
		}, nil
	}
}

func newServer(t *testing.T, ps ...plugins.Plugin) *compattest.Server {
	t.Helper()
	opts := make([]compattest.Option, 0, len(ps)+1)
	for _, p := range ps {
		opts = append(opts, compattest.WithPlugin(p))
	}
	return compattest.NewServer(t, opts...)
}

func signUp(t *testing.T, s *compattest.Server, email string) {
	t.Helper()
	r := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Custom"})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
}

func TestGetSessionIsCustomized(t *testing.T) {
	var calls atomic.Int32
	s := newServer(t, customsession.New(rolesFn(&calls)))

	// Step 1: no session → null, the callback is not called
	r := s.Get(t, "/api/auth/get-session")
	if r.Status != http.StatusOK || string(r.Body) != "null" && string(r.Body) != "null\n" {
		t.Fatalf("no session = %d %q", r.Status, r.Body)
	}
	if calls.Load() != 0 {
		t.Fatal("callback called without a session")
	}

	// Step 2: signed in → the callback's value, with the core headers kept
	signUp(t, s, "custom@example.com")
	r = s.Get(t, "/api/auth/get-session")
	if r.Status != http.StatusOK {
		t.Fatalf("get-session = %d: %s", r.Status, r.Body)
	}
	var body struct {
		Roles   []string       `json:"roles"`
		User    map[string]any `json:"user"`
		Session map[string]any `json:"session"`
	}
	r.JSON(t, &body)
	if len(body.Roles) != 1 || body.Roles[0] != "editor" || body.User["email"] != "custom@example.com" ||
		body.User["newField"] != "custom" || body.Session["token"] == nil || body.Session["userId"] != body.User["id"] {
		t.Fatalf("body = %s", r.Body)
	}
	if cc := r.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	if !jsonContentType(r) {
		t.Fatalf("content-type = %q", r.Header.Get("Content-Type"))
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func jsonContentType(r *compattest.Response) bool {
	return r.Header.Get("Content-Type") == "application/json"
}

func TestRawCarriesPluginFields(t *testing.T) {
	var seen atomic.Value
	fn := func(_ context.Context, s *csconfig.Session) (any, error) {
		user, _ := s.Raw["user"].(map[string]any)
		seen.Store(user)
		return map[string]any{"username": user["username"], "typedName": s.User.Name}, nil
	}
	s := newServer(t, username.New(usernameconfig.UsernameConfig{}), customsession.New(fn))
	r := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "u@example.com", "password": password, "name": "Typed", "username": "raw_user"})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	r = s.Get(t, "/api/auth/get-session")
	if string(r.Body) != `{"typedName":"Typed","username":"raw_user"}`+"\n" && string(r.Body) != `{"typedName":"Typed","username":"raw_user"}` {
		t.Fatalf("body = %s", r.Body)
	}
}

func TestCallbackError(t *testing.T) {
	fn := func(context.Context, *csconfig.Session) (any, error) {
		return nil, autherr.New("FORBIDDEN", "no custom session for you", http.StatusForbidden)
	}
	s := newServer(t, customsession.New(fn))
	signUp(t, s, "err@example.com")
	r := s.Get(t, "/api/auth/get-session")
	if r.Status != http.StatusForbidden {
		t.Fatalf("status = %d: %s", r.Status, r.Body)
	}
	var e struct{ Code, Message string }
	r.JSON(t, &e)
	if e.Code != "FORBIDDEN" || e.Message != "no custom session for you" {
		t.Fatalf("error = %s", r.Body)
	}

	// an unknown error is an internal error, never leaked
	s = newServer(t, customsession.New(func(context.Context, *csconfig.Session) (any, error) {
		return nil, errors.New("database exploded")
	}))
	signUp(t, s, "err2@example.com")
	r = s.Get(t, "/api/auth/get-session")
	if r.Status != http.StatusInternalServerError {
		t.Fatalf("status = %d: %s", r.Status, r.Body)
	}
	if json.Valid(r.Body) && string(r.Body) != "" {
		var e struct{ Message string }
		r.JSON(t, &e)
		if e.Message == "database exploded" {
			t.Fatal("internal error leaked")
		}
	}
}

func TestCookieCache(t *testing.T) {
	var calls atomic.Int32
	enabled := true
	p := customsession.New(rolesFn(&calls))
	s := compattest.NewServer(t, compattest.WithPlugin(p), compattest.WithConfig(func(c *config.AuthConfig) {
		c.Session.CookieCache = &config.CookieCache{Enabled: &enabled}
	}))
	signUp(t, s, "cache@example.com")
	// served from the session_data cookie, still customized
	r := s.Get(t, "/api/auth/get-session")
	var body struct{ Roles []string }
	r.JSON(t, &body)
	if len(body.Roles) != 1 {
		t.Fatalf("cookie cache body = %s", r.Body)
	}
	// disableCookieCache reads the database, still customized
	r = s.Get(t, "/api/auth/get-session?disableCookieCache=true")
	r.JSON(t, &body)
	if len(body.Roles) != 1 {
		t.Fatalf("db body = %s", r.Body)
	}
}

func TestListDeviceSessions(t *testing.T) {
	for _, mutate := range []bool{true, false} {
		var calls atomic.Int32
		s := newServer(t,
			multisession.New(msconfig.MultiSessionConfig{}),
			customsession.New(rolesFn(&calls), customsession.WithMutateListDeviceSessions(mutate)),
		)
		signUp(t, s, "one@example.com")
		signUp(t, s, "two@example.com")
		before := calls.Load()
		r := s.Get(t, "/api/auth/multi-session/list-device-sessions")
		if r.Status != http.StatusOK {
			t.Fatalf("list = %d: %s", r.Status, r.Body)
		}
		var list []map[string]any
		r.JSON(t, &list)
		if len(list) != 2 {
			t.Fatalf("list = %s", r.Body)
		}
		_, customized := list[0]["roles"]
		if customized != mutate {
			t.Fatalf("mutate=%v but body = %s", mutate, r.Body)
		}
		if mutate && calls.Load()-before != 2 {
			t.Fatalf("calls = %d", calls.Load()-before)
		}
	}
}

func TestMissingCallback(t *testing.T) {
	p := customsession.New(nil)
	if err := p.Init(&plugins.InitContext{}); err == nil {
		t.Fatal("nil callback accepted")
	}
}

func TestConcurrentGetSession(t *testing.T) {
	var calls atomic.Int32
	s := newServer(t, customsession.New(rolesFn(&calls)))
	signUp(t, s, "conc@example.com")
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := s.Get(t, "/api/auth/get-session")
			var body struct{ Roles []string }
			if json.Unmarshal(r.Body, &body) != nil || len(body.Roles) != 1 {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d bad responses", bad.Load())
	}
}
