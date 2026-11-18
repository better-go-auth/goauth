// Package haveibeenpwnedclient runs the official better-auth client against goauth's have-i-been-pwned plugin.
package haveibeenpwnedclient

import (
	"crypto/sha1" //nolint:gosec // the range API is keyed by SHA-1
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/haveibeenpwned"
	hibpconfig "github.com/better-go-auth/goauth/src/plugins/haveibeenpwned/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const pwned = "password123"

func TestOfficialClientHaveIBeenPwned(t *testing.T) {
	// Step 1: a fake range API that knows one breached password
	sum := sha1.Sum([]byte(pwned)) //nolint:gosec // test corpus
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.URL.Path, "/range/") == hash[:5] {
			_, _ = fmt.Fprintf(w, "%s:99\r\n", hash[5:])
		}
		_, _ = fmt.Fprint(w, "0000000000000000000000000000000000A:0")
	}))
	t.Cleanup(api.Close)

	// Step 2: goauth with the plugin
	s := compattest.NewServer(t,
		compattest.WithPlugin(haveibeenpwned.New(hibpconfig.HaveIBeenPwnedConfig{APIURL: api.URL + "/range/"})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 3: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-haveibeenpwned.mjs", s.URL, "PWNED_PASSWORD="+pwned)
}
