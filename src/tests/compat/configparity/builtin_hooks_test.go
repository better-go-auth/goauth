package configparity

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// challengePlugin registers goauth's built-in hooks like two-factor (OnAfterSignIn) and anonymous
// (OnNewSession) do, and records what they see.
type challengePlugin struct {
	rec *recorder
}

func (p *challengePlugin) ID() string                        { return "challenge" }
func (p *challengePlugin) Migrator() migration.IMigrator     { return nil }
func (p *challengePlugin) Services() map[string]any          { return nil }
func (p *challengePlugin) Routes() []plugins.RouteDescriptor { return nil }
func (p *challengePlugin) Init(ictx *plugins.InitContext) error {
	ictx.Hooks.OnAfterSignIn(func(ctx context.Context, ev plugins.SignInEvent) (*plugins.SignInChallenge, error) {
		p.rec.add("interceptor:" + ev.Path + ":" + ev.Session.User.Email)
		// challenge users whose e-mail starts with "2fa"; let the others through with an extra cookie
		if strings.HasPrefix(ev.Session.User.Email, "2fa") {
			return &plugins.SignInChallenge{
				Body:    map[string]any{"twoFactorRedirect": true},
				Cookies: []http.Cookie{{Name: "challenge", Value: "pending", Path: "/"}},
			}, nil
		}
		return &plugins.SignInChallenge{ExtraCookies: []http.Cookie{{Name: "extra", Value: "1", Path: "/"}}}, nil
	})
	ictx.Hooks.OnNewSession(func(ctx context.Context, ev plugins.NewSessionEvent) error {
		p.rec.add("new-session:" + ev.Path)
		return nil
	})
	return nil
}

// TestBuiltinHooksOnSignIn: the user's after hook runs first and sees the session the sign-in created; then
// the sign-in interceptor may replace the response (no session cookie is sent and new-session hooks do not
// fire) or let it through with extra cookies.
func TestBuiltinHooksOnSignIn(t *testing.T) {
	rec := &recorder{}
	s := compattest.NewServer(t,
		compattest.WithPlugin(&challengePlugin{rec: rec}),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.Hooks.After = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
				if c.Path == "/sign-in/email" {
					if ns := c.NewSession(); ns != nil {
						rec.add("user-after:" + ns.User.Email)
					}
				}
				return nil, nil
			}
		}))
	signUp(t, s, "2fa-user@example.com")
	signUp(t, s, "plain@example.com")
	rec.reset()

	// Step 1: challenged sign-in
	res := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "2fa-user@example.com", "password": password})
	if res.Status != http.StatusOK || strings.TrimSpace(string(res.Body)) != `{"twoFactorRedirect":true}` {
		t.Fatalf("challenge: %d %s", res.Status, res.Body)
	}
	if ck := res.Cookie("better-auth.session_token"); ck != nil && ck.Value != "" {
		t.Fatalf("session cookie sent with a challenge: %v", ck)
	}
	if res.Cookie("challenge") == nil {
		t.Fatal("challenge cookie missing")
	}
	want := []string{"user-after:2fa-user@example.com", "interceptor:/sign-in/email:2fa-user@example.com"}
	if got := rec.list(); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %v\nwant    %v", got, want)
	}

	// Step 2: sign-in that goes through: extra cookie added, new-session hooks fire
	rec.reset()
	res = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "plain@example.com", "password": password})
	if res.Status != http.StatusOK || res.Cookie("better-auth.session_token") == nil || res.Cookie("extra") == nil {
		t.Fatalf("plain sign-in: %d %v", res.Status, res.Header.Values("Set-Cookie"))
	}
	want = []string{"user-after:plain@example.com", "interceptor:/sign-in/email:plain@example.com", "new-session:/sign-in/email"}
	if got := rec.list(); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %v\nwant    %v", got, want)
	}

	// Step 3: sign-up creates a session too, but interceptors only run on credential sign-in paths
	rec.reset()
	signUp(t, s, "2fa-new@example.com")
	if got := rec.list(); !reflect.DeepEqual(got, []string{"new-session:/sign-up/email"}) {
		t.Fatalf("sign-up calls = %v", got)
	}
}
