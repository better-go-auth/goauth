// Package onetapclient runs the official better-auth client (oneTapClient) against goauth's one-tap plugin.
//
// oneTapClient's oneTap() action needs a browser (it loads Google Identity Services and shows the prompt);
// in Node it returns undefined, which the script checks. The script then sends Google's credential the
// way oneTap() does, through the official client's $fetch("/one-tap/callback"), with ID tokens minted
// here by a fake Google key set.
package onetapclient

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	onetap "github.com/better-go-auth/goauth/src/plugins/one-tap"
	onetapconfig "github.com/better-go-auth/goauth/src/plugins/one-tap/config"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const clientID = "compat-client.apps.googleusercontent.com"

func newServer(t *testing.T, google *socialtest.Provider, disableSignup bool) *compattest.Server {
	t.Helper()
	p := onetap.New(onetapconfig.OneTapConfig{ClientID: clientID, DisableSignup: disableSignup, JWKSURL: google.JWKSEndpoint()})
	return compattest.NewServer(t, compattest.WithPlugin(p), compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = "http://localhost:3000"
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
	}))
}

func TestOfficialClientOneTap(t *testing.T) {
	// Step 1: a fake Google key set and the two servers (default and disableSignup)
	google := socialtest.New(clientID, "unused")
	google.Issuer = "https://accounts.google.com"
	t.Cleanup(google.Close)
	s := newServer(t, google, false)
	disabled := newServer(t, google, true)

	// Step 2: the ID tokens the script sends
	user := socialtest.Profile{Sub: "onetap-sub-1", Email: "OneTap.User@Example.com", EmailVerified: true, Name: "One Tap"}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{
		"TOKEN_NEW":            google.SignIDToken(user, "", nil),
		"TOKEN_SAME":           google.SignIDToken(user, "", nil),
		"TOKEN_WRONG_AUDIENCE": google.SignIDToken(user, "", map[string]any{"aud": "another-client"}),
		"TOKEN_BAD_SIGNATURE":  google.SignIDTokenWithKey(other, user, "", nil),
		"TOKEN_NO_EMAIL":       google.SignIDToken(socialtest.Profile{Sub: "no-email", Name: "Nobody"}, "", nil),
		"TOKEN_LINK":           google.SignIDToken(socialtest.Profile{Sub: "link-sub", Email: "onetap.link@example.com", EmailVerified: true, Name: "Link"}, "", nil),
	}
	env := []string{"GOAUTH_URL_DISABLED=" + disabled.URL, "GOOGLE_CLIENT_ID=" + clientID}
	for k, v := range tokens {
		env = append(env, k+"="+v)
	}

	// Step 3: run the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-one-tap.mjs", s.URL, env...)
}
