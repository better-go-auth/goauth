package test

import (
	"testing"

	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
)

// TestWithBearerPlugins: the bearer and access-token plugins read Authorization: Bearer too; an OAuth
// access token at /oauth2/userinfo must still reach the oidc-provider.
func TestWithBearerPlugins(t *testing.T) {
	at := accesstokenconfig.DefaultAccessTokenConfig()
	at.AutoRegisterMiddleware = true
	e := newEnv(t, oidcconfig.Config{TrustedClients: []oidcconfig.Client{trusted}},
		bearer.New(bearerconfig.BearerConfig{}), accesstoken.New(at))
	c := &codeEnv{env: e, user: e.srv.Browser()}
	c.userID = c.user.SignUp("bearer@example.com", "Bear Er")
	tok := c.exchange(c.code(nil), nil)
	if tok.Status != 200 {
		t.Fatalf("token: %s", tok)
	}
	r := e.srv.Browser().Get(e.srv.Path("/oauth2/userinfo"), map[string]string{"Authorization": "Bearer " + tok.JSON()["access_token"].(string)})
	if r.Status != 200 || r.JSON()["sub"] != c.userID {
		t.Fatalf("userinfo behind bearer plugins: %s", r)
	}
}
