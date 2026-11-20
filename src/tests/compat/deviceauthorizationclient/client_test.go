// Package deviceauthorizationclient runs the official better-auth client (deviceAuthorizationClient)
// against goauth.
package deviceauthorizationclient

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	deviceauthorization "github.com/better-go-auth/goauth/src/plugins/device-authorization"
	daconfig "github.com/better-go-auth/goauth/src/plugins/device-authorization/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientDeviceAuthorization(t *testing.T) {
	// Step 1: goauth with the device-authorization plugin (1 s polling, two known clients) and the bearer
	// plugin, so the issued session token works as a bearer token
	noSig := false
	s := compattest.NewServer(t,
		compattest.WithPlugin(deviceauthorization.New(daconfig.DeviceAuthorizationConfig{
			Interval: time.Second,
			ValidateClient: func(_ context.Context, clientID string) (bool, error) {
				return clientID == "cli" || clientID == "tv", nil
			},
		})),
		compattest.WithPlugin(bearer.New(bearerconfig.BearerConfig{RequireSignature: &noSig})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 2: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-device-authorization.mjs", s.URL)
}
