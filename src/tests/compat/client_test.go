package compattest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	bearer "github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
)

func TestOfficialBetterAuthClient(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed, skipping official better-auth/client test")
	}

	clientScript := filepath.Join("client", "test-flow.mjs")
	if _, err := os.Stat(clientScript); err != nil {
		t.Fatalf("client test script not found: %v", err)
	}

	s := NewServer(t, WithConfig(func(c *config.AuthConfig) {
		compatMode(c)
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
	}))

	cmd := exec.Command("node", "test-flow.mjs")
	cmd.Dir = "client"
	cmd.Env = append(os.Environ(), "GOAUTH_URL="+s.URL)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official better-auth/client test failed: %v\nOutput:\n%s", err, string(output))
	}

	t.Logf("official better-auth/client output:\n%s", string(output))
}

func TestOfficialBetterAuthClient_Bearer(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed, skipping official better-auth/client bearer test")
	}

	clientScript := filepath.Join("client", "test-bearer.mjs")
	if _, err := os.Stat(clientScript); err != nil {
		t.Fatalf("client test script not found: %v", err)
	}

	s := NewServer(t,
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	cmd := exec.Command("node", "test-bearer.mjs")
	cmd.Dir = "client"
	cmd.Env = append(os.Environ(), "GOAUTH_URL="+s.URL)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official better-auth/client bearer test failed: %v\nOutput:\n%s", err, string(output))
	}

	t.Logf("official better-auth/client bearer output:\n%s", string(output))
}

func TestOfficialBetterAuthClient_JWT(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed, skipping official better-auth/client jwt test")
	}

	clientScript := filepath.Join("client", "test-jwt.mjs")
	if _, err := os.Stat(clientScript); err != nil {
		t.Fatalf("client test script not found: %v", err)
	}

	s := NewServer(t,
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(jwtplugin.New(jwtconfig.DefaultConfig())),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	cmd := exec.Command("node", "test-jwt.mjs")
	cmd.Dir = "client"
	cmd.Env = append(os.Environ(), "GOAUTH_URL="+s.URL)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official better-auth/client jwt test failed: %v\nOutput:\n%s", err, string(output))
	}

	t.Logf("official better-auth/client jwt output:\n%s", string(output))
}


