package configparity

import (
	"context"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// hookCtxKey is the context key TestHooksBeforeContextValue attaches in a before hook.
type hookCtxKey struct{}

// ctxPlugin mounts GET /ctx-plugin/value, which answers the context value a before hook attached, and the
// before hook itself.
type ctxPlugin struct{ testPlugin }

type ctxValueOutput struct {
	Body struct {
		Value   string `json:"value"`
		BaseURL string `json:"baseURL"`
	}
}

func (p *ctxPlugin) Init(ictx *plugins.InitContext) error {
	kit, err := pluginkit.New(ictx)
	if err != nil {
		return err
	}
	pluginkit.Register(kit, ictx.Api, pluginkit.Route{
		OperationID: "ctxPluginValue", Method: http.MethodGet, Path: "/ctx-plugin/value", Access: pluginkit.Public,
	}, func(ctx context.Context, _ *struct{}) (*ctxValueOutput, error) {
		out := &ctxValueOutput{}
		out.Body.Value, _ = ctx.Value(hookCtxKey{}).(string)
		out.Body.BaseURL = kit.RequestBaseURL(ctx)
		return out, nil
	})
	return nil
}

// TestHooksBeforeContextValue: a before hook may replace c.Ctx with a derived context; the endpoint runs with
// it. pluginkit.WithBaseURL uses this for better-auth's `ctx.context.baseURL = ...` (oauth-proxy).
func TestHooksBeforeContextValue(t *testing.T) {
	p := &ctxPlugin{testPlugin{id: "ctx-plugin"}}
	p.hooks = endpointhooks.Hooks{Before: []endpointhooks.BeforeHook{{
		Matcher: endpointhooks.MatchPaths("/ctx-plugin/value"),
		Handler: func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			if v := c.Query.Get("set"); v != "" {
				c.Ctx = context.WithValue(c.Ctx, hookCtxKey{}, v)
				c.Ctx = pluginkit.WithBaseURL(c.Ctx, "https://prod.example.com/api/auth")
			}
			return nil, nil
		},
	}}}
	s := compattest.NewServer(t, compattest.WithPlugin(p))
	for _, tc := range []struct{ query, value, base string }{
		{"?set=from-hook", "from-hook", "https://prod.example.com/api/auth"},
		{"", "", "http://127.0.0.1:8080/api/auth"},
	} {
		res := s.Get(t, "/api/auth/ctx-plugin/value"+tc.query)
		var out struct {
			Value   string `json:"value"`
			BaseURL string `json:"baseURL"`
		}
		res.JSON(t, &out)
		if res.Status != http.StatusOK || out.Value != tc.value || out.BaseURL != tc.base {
			t.Fatalf("query %q: %d %+v, want value=%q base=%q", tc.query, res.Status, out, tc.value, tc.base)
		}
	}
}
