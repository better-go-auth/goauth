package cookies

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
)

type cookieVectors struct {
	Secret          string `json:"secret"`
	CookieValue     string `json:"cookieValue"`
	CookieSignature string `json:"cookieSignature"`
}

func TestSignedCookieMatchesBetterAuth(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "authcrypto", "testdata", "better_auth_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v cookieVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	signed := SignCookieValue(v.CookieValue, v.Secret)
	if signed != v.CookieValue+"."+v.CookieSignature {
		t.Fatalf("signature mismatch: %s", signed)
	}
	if got, ok := VerifyCookieValue(signed, v.Secret); !ok || got != v.CookieValue {
		t.Fatalf("verify: %q %v", got, ok)
	}
	if _, ok := VerifyCookieValue(signed, "other"); ok {
		t.Fatal("wrong secret must fail")
	}
	if _, ok := VerifyCookieValue(v.CookieValue+".tampered", v.Secret); ok {
		t.Fatal("tampered signature must fail")
	}
	enc := EncodeCookieValue(signed)
	if strings.ContainsAny(enc, "+/=") {
		t.Fatalf("encoded value must escape base64 symbols: %s", enc)
	}
	if DecodeCookieValue(enc) != signed {
		t.Fatal("decode must reverse encode")
	}
}

func newTestCookies(baseURL string) *Manager {
	conf := config.AuthConfig{BaseURL: baseURL, Secret: "s3cret-s3cret-s3cret-s3cret-s3cret"}
	conf.SetDefaults()
	return New(conf)
}

func TestCookiesSessionRoundTrip(t *testing.T) {
	c := newTestCookies("http://localhost:3000")
	set := c.SessionCookies("tok123", false)
	if len(set) != 1 || set[0].Name != "better-auth.session_token" || set[0].MaxAge != 7*24*3600 {
		t.Fatalf("unexpected cookies %+v", set)
	}
	if !set[0].HttpOnly || set[0].Secure || set[0].SameSite != http.SameSiteLaxMode || set[0].Path != "/" {
		t.Fatalf("unexpected attributes %+v", set[0])
	}
	header := set[0].Name + "=" + set[0].Value
	if tok, ok := c.SessionToken(header); !ok || tok != "tok123" {
		t.Fatalf("read back: %q %v", tok, ok)
	}
	if c.DontRemember(header) {
		t.Fatal("dont_remember must be absent")
	}
	if _, ok := c.SessionToken("better-auth.session_token=tok123.forged"); ok {
		t.Fatal("unsigned cookie must be rejected")
	}
}

func TestCookiesDontRememberAndSecure(t *testing.T) {
	c := newTestCookies("https://auth.example.com")
	set := c.SessionCookies("tok", true)
	if len(set) != 2 || set[0].MaxAge != 0 || set[1].Name != "__Secure-better-auth.dont_remember" || !set[0].Secure {
		t.Fatalf("unexpected cookies %+v", set)
	}
	header := set[0].Name + "=" + set[0].Value + "; " + set[1].Name + "=" + set[1].Value
	if tok, ok := c.SessionToken(header); !ok || tok != "tok" || !c.DontRemember(header) {
		t.Fatalf("read back failed: %q %v", tok, ok)
	}
	for _, ck := range c.ExpireSessionCookies() {
		if ck.MaxAge >= 0 || !strings.HasPrefix(ck.Name, "__Secure-better-auth.") {
			t.Fatalf("unexpected expire cookie %+v", ck)
		}
	}
}
