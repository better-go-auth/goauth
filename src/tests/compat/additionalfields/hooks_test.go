package additionalfields

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/dbhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/migration"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/stretchr/testify/require"
)

// recorder collects hook calls in order.
type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.events
	r.events = nil
	return out
}

// hooksPlugin is a plugin with database hooks (better-auth's plugin init returning options.databaseHooks)
// and a typed HookRegistry hook.
type hooksPlugin struct{ rec *recorder }

func (p *hooksPlugin) ID() string                       { return "hooks-test" }
func (p *hooksPlugin) Migrator() migration.IMigrator    { return nil }
func (p *hooksPlugin) Services() map[string]any         { return nil }
func (p *hooksPlugin) Routes() []plugin.RouteDescriptor { return nil }
func (p *hooksPlugin) Init(ictx *plugin.InitContext) error {
	// the typed hook runs first (goauth's HookRegistry), then plugin database hooks, then the config's
	ictx.Hooks.OnBeforeUserCreate(func(_ context.Context, u *models.User) error {
		p.rec.add("typed:before:" + u.Email)
		return nil
	})
	return nil
}
func (p *hooksPlugin) DatabaseHooks() dbhooks.Hooks {
	return dbhooks.Hooks{User: dbhooks.ModelHooks[models.User]{Create: dbhooks.CreateHooks[models.User]{
		Before: func(_ context.Context, u *models.User) error {
			p.rec.add("plugin:before:" + u.Email)
			u.SetExtra("plan", "plugin-plan")
			return nil
		},
	}}}
}

// TestDatabaseHooksEndToEnd covers AuthConfig.DatabaseHooks through the HTTP API: modify, cancel, errors,
// after hooks, update hooks, session / account / verification hooks and the order of the sources.
func TestDatabaseHooksEndToEnd(t *testing.T) {
	rec := &recorder{}
	cfgHooks := dbhooks.Hooks{
		User: dbhooks.ModelHooks[models.User]{
			Create: dbhooks.CreateHooks[models.User]{
				Before: func(_ context.Context, u *models.User) error {
					rec.add("user:before:" + u.Email)
					switch {
					case strings.HasPrefix(u.Email, "blocked"):
						return dbhooks.ErrCancel
					case strings.HasPrefix(u.Email, "forbidden"):
						return autherr.ErrForbidden.WithMessage("sign-ups from this domain are closed")
					}
					// better-auth's `return { data: { ...user, plan } }`, after the plugin's change
					if p, _ := u.GetExtra("plan"); p == "plugin-plan" {
						u.SetExtra("plan", "hooked")
					}
					return nil
				},
				After: func(_ context.Context, u *models.User) error {
					p, _ := u.GetExtra("plan")
					rec.add("user:after:" + u.Email + ":" + p.(string))
					return nil
				},
			},
			Update: dbhooks.UpdateHooks[models.User]{
				Before: func(ctx context.Context, data map[string]any) error {
					if data["plan"] == "cancel" {
						return dbhooks.ErrCancel
					}
					if data["plan"] == "fail" {
						return autherr.Err(http.StatusBadRequest, "PLAN_REJECTED", "plan rejected")
					}
					if _, ok := data["plan"]; ok {
						data["plan"] = strings.ToUpper(data["plan"].(string))
					}
					rec.add("user:update:" + dbhooks.Target(ctx))
					return nil
				},
				After: func(_ context.Context, u *models.User) error {
					rec.add("user:updated:" + u.Name)
					return nil
				},
			},
			Delete: dbhooks.DeleteHooks[models.User]{
				After: func(_ context.Context, u *models.User) error {
					rec.add("user:deleted:" + u.Email)
					return nil
				},
			},
		},
		Session: dbhooks.ModelHooks[models.Session]{Create: dbhooks.CreateHooks[models.Session]{
			Before: func(_ context.Context, s *models.Session) error {
				s.SetExtra("deviceLabel", "set-by-hook")
				return nil
			},
		}},
		Account: dbhooks.ModelHooks[models.Account]{Create: dbhooks.CreateHooks[models.Account]{
			After: func(_ context.Context, a *models.Account) error {
				rec.add("account:" + string(a.ProviderID))
				return nil
			},
		}},
		Verification: dbhooks.ModelHooks[models.Verification]{Create: dbhooks.CreateHooks[models.Verification]{
			After: func(_ context.Context, v *models.Verification) error {
				rec.add("verification:" + strings.SplitN(v.Identifier, ":", 2)[0])
				return nil
			},
		}},
	}
	s := compattest.NewServer(t, compattest.WithDB(openDB(t)), compattest.WithConfig(func(c *config.AuthConfig) {
		c.User.AdditionalFields = userFields()
		c.Session.AdditionalFields = sessionFields()
		c.DatabaseHooks = cfgHooks
		c.User.DeleteUser.Enabled = true
		c.EmailAndPassword.SendResetPassword = func(config.ResetPasswordData, *http.Request) error { return nil }
	}), withPlugins(&hooksPlugin{rec: rec}))

	// Step 1: create: typed → plugin → config, the stored user has the hooks' change, after hooks run last
	res := signUp(t, s, "hooked@example.com", nil)
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Equal(t, "hooked", object(t, jsonBody(t, res), "user")["plan"])
	require.Equal(t, []string{
		"typed:before:hooked@example.com", "plugin:before:hooked@example.com", "user:before:hooked@example.com",
		// after hooks wait for the sign-up transaction and run in the order they were queued
		"user:after:hooked@example.com:hooked", "account:credential",
	}, rec.take())
	// the session create hook set an additional session field
	require.Equal(t, "set-by-hook", object(t, getSession(t, s), "session")["deviceLabel"])

	// Step 2: cancel → better-auth's 400 FAILED_TO_CREATE_USER; a hook's error reaches the client as is
	s.Jar.SetCookies(nil, nil)
	requireError(t, signUp(t, s, "blocked@example.com", nil), 400, "FAILED_TO_CREATE_USER", "Failed to create user")
	requireError(t, signUp(t, s, "forbidden@example.com", nil), 403, "FORBIDDEN", "sign-ups from this domain are closed")
	stored, _ := s.Auth.Repositories().FindUserByEmail(t.Context(), "blocked@example.com")
	require.Nil(t, stored, "a cancelled user must not be stored")
	rec.take()

	// Step 3: update hooks change the data, see the target user, run after; cancel keeps the user
	require.Equal(t, http.StatusOK, s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "hooked@example.com", "password": password}).Status)
	userID := object(t, getSession(t, s), "user")["id"].(string)
	rec.take()
	require.Equal(t, http.StatusOK, s.Post(t, "/api/auth/update-user", map[string]any{"plan": "pro", "name": "Renamed"}).Status)
	require.Equal(t, "PRO", object(t, getSession(t, s), "user")["plan"])
	require.Equal(t, []string{"user:update:" + userID, "user:updated:Renamed"}, rec.take())
	res = s.Post(t, "/api/auth/update-user", map[string]any{"plan": "cancel"})
	require.Equal(t, http.StatusOK, res.Status, "a cancelled update answers like better-auth (status true): %s", res.Body)
	require.Equal(t, "PRO", object(t, getSession(t, s), "user")["plan"])
	requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"plan": "fail"}), 400, "PLAN_REJECTED", "plan rejected")

	// Step 4: verification hooks (password reset token)
	rec.take()
	require.Equal(t, http.StatusOK, s.Post(t, "/api/auth/request-password-reset", map[string]any{"email": "hooked@example.com"}).Status)
	require.Contains(t, rec.take(), "verification:reset-password")

	// Step 5: delete hooks
	res = s.Post(t, "/api/auth/delete-user", map[string]any{"password": password})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Contains(t, rec.take(), "user:deleted:hooked@example.com")
}

// TestSessionCreateCancel: a session create hook that cancels makes sign-in answer better-auth's
// 401 FAILED_TO_CREATE_SESSION (sign-up: 400).
func TestSessionCreateCancel(t *testing.T) {
	cancel := false
	s := compattest.NewServer(t, compattest.WithDB(openDB(t)), compattest.WithConfig(func(c *config.AuthConfig) {
		c.DatabaseHooks.Session.Create.Before = func(context.Context, *models.Session) error {
			if cancel {
				return dbhooks.ErrCancel
			}
			return nil
		}
	}), withPlugins())
	require.Equal(t, http.StatusOK, signUp(t, s, "sess-cancel@example.com", nil).Status)
	cancel = true
	requireError(t, s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "sess-cancel@example.com", "password": password}),
		401, "FAILED_TO_CREATE_SESSION", "Failed to create session")
	s.Jar.SetCookies(nil, nil)
	requireError(t, signUp(t, s, "sess-cancel2@example.com", nil), 400, "FAILED_TO_CREATE_SESSION", "")
}
