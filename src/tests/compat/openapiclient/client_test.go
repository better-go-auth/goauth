// Package openapiclient checks goauth's open-api plugin with the official better-auth client and against
// the document and reference page better-auth itself generates for the same plugins.
package openapiclient

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	onetimetoken "github.com/better-go-auth/goauth/src/plugins/one-time-token"
	ottconfig "github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
	openapi "github.com/better-go-auth/goauth/src/plugins/open-api"
	openapiconfig "github.com/better-go-auth/goauth/src/plugins/open-api/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientOpenAPI(t *testing.T) {
	// Step 1: goauth with the plugins the script also installs in better-auth
	s := compattest.NewServer(t,
		compattest.WithPlugin(openapi.New(openapiconfig.OpenAPIConfig{})),
		compattest.WithPlugin(onetimetoken.New(ottconfig.OneTimeTokenConfig{})),
		compattest.WithPlugin(username.New(usernameconfig.UsernameConfig{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)
	// Step 2: run the script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-open-api.mjs", s.URL)
}
