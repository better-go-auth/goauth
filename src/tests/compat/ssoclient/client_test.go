// Package ssoclient runs the official @better-auth/sso client (src/tests/compat/client-sso/test-sso.mjs)
// against goauth's sso plugin with an in-process fake OIDC identity provider.
package ssoclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	"github.com/better-go-auth/goauth/src/plugins/sso"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const appBase = "http://localhost:3000"

// certPEM is a self-signed RSA certificate for the SAML registration.
func certPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestOfficialSSOClient(t *testing.T) {
	// Step 1: the fake OIDC identity provider
	fake := socialtest.New("sso-client-id", "sso-client-secret")
	t.Cleanup(fake.Close)
	// Step 2: goauth with the sso plugin (the fake IdP on 127.0.0.1 is a trusted origin)
	s := compattest.NewServer(t,
		compattest.WithPlugin(sso.New(ssoconfig.SSOConfig{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = appBase
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}))
	fake.SetRedirectBase(s.URL)
	// Step 3: run the official client
	compattest.RunNodeClient(t, compattest.ClientDir("client-sso"), "test-sso.mjs", s.URL,
		"GOAUTH_APP_BASE="+appBase,
		"SSO_ISSUER="+fake.Issuer,
		"SSO_CLIENT_ID="+fake.ClientID,
		"SSO_CLIENT_SECRET="+fake.ClientSecret,
		"SSO_PROVIDER_EMAIL=fake.user@example.com",
		"SAML_CERT="+certPEM(t),
	)
}
