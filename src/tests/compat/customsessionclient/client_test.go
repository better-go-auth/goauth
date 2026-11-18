// Package customsessionclient runs the official better-auth client (customSessionClient, multiSessionClient)
// against goauth's custom-session plugin.
package customsessionclient

import (
	"context"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	customsession "github.com/better-go-auth/goauth/src/plugins/custom-session"
	csconfig "github.com/better-go-auth/goauth/src/plugins/custom-session/config"
	multisession "github.com/better-go-auth/goauth/src/plugins/multi-session"
	msconfig "github.com/better-go-auth/goauth/src/plugins/multi-session/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// fn is the documented better-auth example: roles plus an extra user field.
func fn(_ context.Context, s *csconfig.Session) (any, error) {
	user := map[string]any{}
	for k, v := range s.Raw["user"].(map[string]any) {
		user[k] = v
	}
	user["newField"] = "custom"
	return map[string]any{"roles": []string{"editor"}, "user": user, "session": s.Raw["session"]}, nil
}

func TestOfficialClientCustomSession(t *testing.T) {
	// Step 1: goauth with multi-session and custom-session (list-device-sessions mutated too)
	s := compattest.NewServer(t,
		compattest.WithPlugin(multisession.New(msconfig.MultiSessionConfig{})),
		compattest.WithPlugin(customsession.New(fn, customsession.WithMutateListDeviceSessions(true))),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 2: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-custom-session.mjs", s.URL)
}
