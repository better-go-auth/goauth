package configparity

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// orderingPlugin declares one before and one after hook on /ok that record their name.
func orderingPlugin(id string, rec *recorder) *testPlugin {
	match := endpointhooks.MatchPaths("/ok")
	return &testPlugin{id: id, hooks: endpointhooks.Hooks{
		Before: []endpointhooks.BeforeHook{{Matcher: match, Handler: func(*endpointhooks.Context) (*endpointhooks.Response, error) {
			rec.add(id + ":before")
			return nil, nil
		}}},
		After: []endpointhooks.AfterHook{{Matcher: match, Handler: func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			rec.add(id + ":after")
			return nil, nil
		}}},
	}}
}

// TestHooksOrder: better-auth's dispatch order: user before, plugin before hooks (plugin order), endpoint,
// user after, plugin after hooks (plugin order). Matchers select the paths.
func TestHooksOrder(t *testing.T) {
	rec := &recorder{}
	s := compattest.NewServer(t,
		compattest.WithPlugin(orderingPlugin("plugin-a", rec)),
		compattest.WithPlugin(orderingPlugin("plugin-b", rec)),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.Hooks.Before = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
				if c.Path == "/ok" {
					rec.add("user:before")
				}
				return nil, nil
			}
			c.Hooks.After = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
				if c.Path == "/ok" {
					rec.add("user:after:" + string(c.Returned.Body[:len(c.Returned.Body)-1]))
				}
				return nil, nil
			}
		}))
	if res := s.Get(t, "/api/auth/ok"); res.Status != http.StatusOK {
		t.Fatalf("/ok: %d", res.Status)
	}
	want := []string{"user:before", "plugin-a:before", "plugin-b:before", `user:after:{"ok":true}`, "plugin-a:after", "plugin-b:after"}
	if got := rec.list(); !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v\nwant    %v", got, want)
	}
	// matchers: another path runs only the user hooks (which ignore it)
	rec.reset()
	s.Get(t, "/api/auth/get-session")
	if got := rec.list(); len(got) != 0 {
		t.Fatalf("hooks ran on another path: %v", got)
	}
}

// TestHooksBeforeShortCircuit: a before hook's response answers instead of the endpoint; later before hooks
// and every after hook are skipped; headers set with SetCookie are sent.
func TestHooksBeforeShortCircuit(t *testing.T) {
	rec := &recorder{}
	p := &testPlugin{id: "test-plugin"}
	p.hooks = endpointhooks.Hooks{
		Before: []endpointhooks.BeforeHook{{Matcher: endpointhooks.MatchPaths("/test-plugin/ping"),
			Handler: func(*endpointhooks.Context) (*endpointhooks.Response, error) {
				rec.add("plugin:before")
				return nil, nil
			}}},
		After: []endpointhooks.AfterHook{{Handler: func(*endpointhooks.Context) (*endpointhooks.Response, error) {
			rec.add("plugin:after")
			return nil, nil
		}}},
	}
	s := compattest.NewServer(t, compattest.WithPlugin(p), compattest.WithConfig(func(c *config.AuthConfig) {
		c.Hooks.Before = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			if c.Path != "/test-plugin/ping" || c.Query.Get("blocked") == "" {
				return nil, nil
			}
			c.SetCookie(&http.Cookie{Name: "hooked", Value: "1", Path: "/"})
			return endpointhooks.JSON(http.StatusTeapot, map[string]any{"blocked": true}), nil
		}
	}))
	res := s.Get(t, "/api/auth/test-plugin/ping?blocked=1")
	if res.Status != http.StatusTeapot || strings.TrimSpace(string(res.Body)) != `{"blocked":true}` {
		t.Fatalf("short-circuit: %d %s", res.Status, res.Body)
	}
	if res.Cookie("hooked") == nil {
		t.Fatal("cookie of the before hook missing")
	}
	if p.pingCount() != 0 || len(rec.list()) != 0 {
		t.Fatalf("endpoint ran %d times, hooks %v", p.pingCount(), rec.list())
	}
	// without the query parameter everything runs
	if res := s.Get(t, "/api/auth/test-plugin/ping"); res.Status != http.StatusOK || p.pingCount() != 1 {
		t.Fatalf("normal request: %d pings=%d", res.Status, p.pingCount())
	}
	if got := rec.list(); !reflect.DeepEqual(got, []string{"plugin:before", "plugin:after"}) {
		t.Fatalf("hooks = %v", got)
	}
}

// TestHooksBeforeErrors: an AuthError keeps its status and better-auth shape and goes to onAPIError.onError;
// any other error is a 500 INTERNAL_SERVER_ERROR.
func TestHooksBeforeErrors(t *testing.T) {
	var reported []error
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.OnAPIError.OnError = func(err error, r *http.Request) {
			if r == nil || !strings.HasSuffix(r.URL.Path, "/sign-up/email") {
				t.Errorf("OnError request = %v", r)
			}
			reported = append(reported, err)
		}
		c.Hooks.Before = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			if c.Path != "/sign-up/email" {
				return nil, nil
			}
			// better-auth's docs example: only some e-mail domains may sign up
			email, _ := c.Body["email"].(string)
			switch {
			case strings.HasSuffix(email, "@blocked.com"):
				return nil, autherr.New("EMAIL_DOMAIN_NOT_ALLOWED", "Email domain not allowed", http.StatusBadRequest)
			case strings.HasSuffix(email, "@broken.com"):
				return nil, errors.New("hook backend down")
			}
			return nil, nil
		}
	}))
	res := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "a@blocked.com", "password": password, "name": "A"})
	if res.Status != http.StatusBadRequest || strings.TrimSpace(string(res.Body)) != `{"code":"EMAIL_DOMAIN_NOT_ALLOWED","message":"Email domain not allowed"}` {
		t.Fatalf("auth error: %d %s", res.Status, res.Body)
	}
	res = s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "a@broken.com", "password": password, "name": "A"})
	if res.Status != http.StatusInternalServerError || !strings.Contains(string(res.Body), `"INTERNAL_SERVER_ERROR"`) || strings.Contains(string(res.Body), "backend") {
		t.Fatalf("internal error: %d %s", res.Status, res.Body)
	}
	if len(reported) != 2 {
		t.Fatalf("OnError got %d errors: %v", len(reported), reported)
	}
	if ae := autherr.AsAuthError(reported[0]); ae == nil || ae.Code != "EMAIL_DOMAIN_NOT_ALLOWED" {
		t.Fatalf("first reported error = %v", reported[0])
	}
	var re *autherr.ReportedError
	if !errors.As(reported[1], &re) || re.Err.Error() != "hook backend down" || re.RequestID == "" {
		t.Fatalf("second reported error = %#v", reported[1])
	}
	// no user was created for either request
	if res := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "a@blocked.com", "password": password}); res.Status != http.StatusUnauthorized {
		t.Fatalf("blocked user exists: %d", res.Status)
	}
}

// TestHooksModifyRequest: before hooks change the JSON body, headers and query the endpoint sees.
func TestHooksModifyRequest(t *testing.T) {
	var sessionCookie string
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.Hooks.Before = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			switch c.Path {
			case "/sign-up/email":
				// body: force the display name
				c.Body["name"] = "Hooked " + c.Body["name"].(string)
			case "/get-session":
				// headers: sign the request in with a stored cookie
				if c.Query.Get("as-user") != "" {
					c.Headers.Set("Cookie", sessionCookie)
					c.Query.Del("as-user")
				}
			}
			return nil, nil
		}
	}))
	res := signUp(t, s, "body@example.com")
	var out struct {
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	}
	res.JSON(t, &out)
	if out.User.Name != "Hooked Test User" {
		t.Fatalf("name = %q", out.User.Name)
	}
	ck := res.Cookie("better-auth.session_token")
	if ck == nil {
		t.Fatal("no session cookie")
	}
	sessionCookie = ck.Name + "=" + ck.Value

	// a fresh client without cookies gets the session the hook injected
	req, _ := http.NewRequest(http.MethodGet, s.URL+"/api/auth/get-session?as-user=1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sess struct {
		User *struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := decodeJSON(resp, &sess); err != nil || sess.User == nil || sess.User.Email != "body@example.com" {
		t.Fatalf("get-session with injected cookie: %v %+v", err, sess)
	}
}

// TestHooksAfterSignIn: the user's after hook sees the sign-in response and the new session
// (better-auth's ctx.context.newSession / returned), can change it in place and replace it.
func TestHooksAfterSignIn(t *testing.T) {
	type seen struct {
		status       int
		sessionEmail string
		token        string
		cookieSet    bool
	}
	var got []seen
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.Hooks.After = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			switch c.Path {
			case "/sign-in/email":
				sv := seen{status: c.Returned.Status}
				if ns := c.NewSession(); ns != nil {
					sv.sessionEmail = ns.User.Email
					sv.token = ns.Session.Token
				}
				for _, ck := range c.Returned.Cookies() {
					if ck.Name == "better-auth.session_token" && ck.Value != "" {
						sv.cookieSet = true
					}
				}
				got = append(got, sv)
				// in-place change
				c.Returned.Header.Set("X-Signed-In", "yes")
			case "/ok":
				// replacement
				return endpointhooks.JSON(http.StatusAccepted, map[string]any{"replaced": true}), nil
			case "/get-session":
				if c.Query.Get("fail") != "" {
					return nil, autherr.New("HOOK_FAILED", "after hook failed", http.StatusConflict)
				}
			}
			return nil, nil
		}
	}))
	signUp(t, s, "after@example.com")
	res := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "after@example.com", "password": password})
	if res.Status != http.StatusOK || res.Header.Get("X-Signed-In") != "yes" {
		t.Fatalf("sign-in: %d %v", res.Status, res.Header)
	}
	var body struct {
		Token string `json:"token"`
	}
	res.JSON(t, &body)
	if len(got) != 1 || got[0].status != http.StatusOK || got[0].sessionEmail != "after@example.com" ||
		got[0].token != body.Token || !got[0].cookieSet {
		t.Fatalf("after hook saw %+v (token %s)", got, body.Token)
	}
	// a failed sign-in has no new session
	s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "after@example.com", "password": "wrong-password"})
	if len(got) != 2 || got[1].status != http.StatusUnauthorized || got[1].sessionEmail != "" {
		t.Fatalf("failed sign-in seen as %+v", got[1])
	}
	// replacement
	if res := s.Get(t, "/api/auth/ok"); res.Status != http.StatusAccepted || strings.TrimSpace(string(res.Body)) != `{"replaced":true}` {
		t.Fatalf("replaced /ok: %d %s", res.Status, res.Body)
	}
	// error
	res = s.Get(t, "/api/auth/get-session?fail=1")
	if res.Status != http.StatusConflict || !strings.Contains(string(res.Body), `"HOOK_FAILED"`) {
		t.Fatalf("after-hook error: %d %s", res.Status, res.Body)
	}
}

// TestHooksPluginAfterSeesBuiltins: plugin after hooks run after goauth's built-in after hooks, so they see
// the final cookies; a before hook's cookie is merged into the endpoint response.
func TestHooksPluginAfterSeesBuiltins(t *testing.T) {
	var newSessionSeen bool
	p := &testPlugin{id: "test-plugin", hooks: endpointhooks.Hooks{
		Before: []endpointhooks.BeforeHook{{Matcher: endpointhooks.MatchPrefix("/sign-in/"), Handler: func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			c.SetCookie(&http.Cookie{Name: "seen_sign_in", Value: "1", Path: "/"})
			return nil, nil
		}}},
		After: []endpointhooks.AfterHook{{Matcher: endpointhooks.MatchPaths("/sign-in/email"), Handler: func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			newSessionSeen = c.NewSession() != nil
			return nil, nil
		}}},
	}}
	s := compattest.NewServer(t, compattest.WithPlugin(p))
	signUp(t, s, "plugin-after@example.com")
	res := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "plugin-after@example.com", "password": password})
	if res.Status != http.StatusOK || res.Cookie("seen_sign_in") == nil || res.Cookie("better-auth.session_token") == nil {
		t.Fatalf("sign-in: %d cookies %v", res.Status, res.Header.Values("Set-Cookie"))
	}
	if !newSessionSeen {
		t.Fatal("plugin after hook did not see the new session")
	}
}

func decodeJSON(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}
