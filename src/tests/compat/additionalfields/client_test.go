package additionalfields

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// TestOfficialClientAdditionalFields runs the official better-auth client with inferAdditionalFields against
// goauth: signUp.email with extra fields, getSession, updateUser, updateSession, signIn.email and the
// input:false / validation errors.
func TestOfficialClientAdditionalFields(t *testing.T) {
	// Step 1: goauth with the additional fields the script's inferAdditionalFields declares
	s := compattest.NewServer(t, compattest.WithDB(openDB(t)), compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = "http://localhost:3000"
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		c.User.AdditionalFields = userFields()
		c.Session.AdditionalFields = sessionFields()
	}), withPlugins())
	// Step 2: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-additional-fields.mjs", s.URL)
}
