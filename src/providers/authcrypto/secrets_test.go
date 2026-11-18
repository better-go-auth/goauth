package authcrypto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
)

// rotationVectors are written by a TypeScript better-auth 1.6 (src/tests/compat/client/gen-secret-vectors.mjs).
type rotationVectors struct {
	LegacySecret     string          `json:"legacySecret"`
	SecretV1         string          `json:"secretV1"`
	SecretV2         string          `json:"secretV2"`
	Plaintext        string          `json:"plaintext"`
	EnvelopeV2       string          `json:"envelopeV2"`
	EnvelopeV1       string          `json:"envelopeV1"`
	BareHexLegacy    string          `json:"bareHexLegacy"`
	SessionData      json.RawMessage `json:"sessionData"`
	JWESessionV2     string          `json:"jweSessionV2"`
	JWESessionV1     string          `json:"jweSessionV1"`
	JWESessionLegacy string          `json:"jweSessionLegacy"`
	JWEExpired       string          `json:"jweExpired"`
	Account          json.RawMessage `json:"account"`
	JWEAccountV2     string          `json:"jweAccountV2"`
}

func loadRotationVectors(t *testing.T) rotationVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "better_auth_rotation_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v rotationVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// keysV2 is the goauth configuration matching the TypeScript server: secrets [v2, v1] + legacy secret.
func keysV2(v rotationVectors) SecretKeys {
	conf := config.AuthConfig{Secret: v.LegacySecret, Secrets: []config.SecretVersion{{Version: 2, Value: v.SecretV2}, {Version: 1, Value: v.SecretV1}}}
	return NewSecretKeys(conf)
}

func TestNewSecretKeysFromConfig(t *testing.T) {
	// Step 1: without Secrets the single secret is used, bare hex in and out
	single := NewSecretKeys(config.AuthConfig{Secret: "only-secret"})
	if single.Versioned() || single.CurrentSecret() != "only-secret" {
		t.Fatalf("single mode: %+v", single)
	}
	// Step 2: with Secrets the first entry is current and the old Secret becomes the legacy secret
	conf := config.AuthConfig{Secret: "legacy", Secrets: []config.SecretVersion{{Version: 3, Value: "v3"}, {Version: 1, Value: "v1"}, {Version: 2, Value: "v2"}}}
	keys := NewSecretKeys(conf)
	if keys.Current != 3 || keys.CurrentSecret() != "v3" || keys.Legacy != "legacy" {
		t.Fatalf("versioned: %+v", keys)
	}
	if got := strings.Join(keys.VerifySecrets(), ","); got != "v3,v2,v1,legacy" {
		t.Fatalf("verify order %q", got)
	}
	// Step 3: after SetDefaults Secret is the current secret, the legacy secret is remembered
	conf.BaseURL = "http://localhost"
	conf.SetDefaults()
	if conf.Secret != "v3" || conf.LegacySecret() != "legacy" {
		t.Fatalf("SetDefaults: secret=%q legacy=%q", conf.Secret, conf.LegacySecret())
	}
	conf.SetDefaults()
	if NewSecretKeys(conf).Legacy != "legacy" {
		t.Fatal("a second SetDefaults must keep the legacy secret")
	}
	// Step 4: the public dev default is never a legacy secret
	dev := config.AuthConfig{Secret: config.DefaultDevSecret, Secrets: []config.SecretVersion{{Version: 1, Value: "v1"}}}
	if NewSecretKeys(dev).Legacy != "" {
		t.Fatal("dev default must not be the legacy secret")
	}
}

func TestSecretKeysReadTypeScriptRotationData(t *testing.T) {
	v := loadRotationVectors(t)
	keys := keysV2(v)

	// Step 1: envelopes of the current and the previous version, and legacy bare hex
	for name, ct := range map[string]string{"v2": v.EnvelopeV2, "v1": v.EnvelopeV1, "legacy": v.BareHexLegacy} {
		got, err := keys.Decrypt(ct)
		if err != nil || got != v.Plaintext {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	// Step 2: a retired version cannot be decrypted any more
	onlyV2 := SecretKeys{Current: 2, Keys: map[int]string{2: v.SecretV2}, Legacy: v.LegacySecret}
	if _, err := onlyV2.Decrypt(v.EnvelopeV1); err == nil || !strings.Contains(err.Error(), "version 1 not found") {
		t.Fatalf("retired version must fail: %v", err)
	}
	// Step 3: an unknown version or a malformed envelope fails
	if _, err := keys.Decrypt("$ba$9$" + strings.TrimPrefix(v.EnvelopeV2, "$ba$2$")); err == nil {
		t.Fatal("unknown version must fail")
	}
	if _, err := keys.Decrypt("$ba$2$zz"); err == nil {
		t.Fatal("bad hex must fail")
	}
	// Step 4: bare hex without a legacy secret fails like better-auth
	if _, err := (SecretKeys{Current: 2, Keys: map[int]string{2: v.SecretV2}}).Decrypt(v.BareHexLegacy); err == nil {
		t.Fatal("bare hex without legacy secret must fail")
	}
}

func TestSecretKeysEncryptUsesCurrentVersion(t *testing.T) {
	v := loadRotationVectors(t)
	keys := keysV2(v)
	// Step 1: new data is a v2 envelope
	ct, err := keys.Encrypt("hello")
	if err != nil || !strings.HasPrefix(ct, "$ba$2$") {
		t.Fatalf("encrypt: %q %v", ct, err)
	}
	// Step 2: decryptable with just the v2 secret (what a TS server holding only v2 would do)
	if got, err := SymmetricDecrypt(v.SecretV2, strings.TrimPrefix(ct, "$ba$2$")); err != nil || got != "hello" {
		t.Fatalf("raw v2 decrypt: %q %v", got, err)
	}
	// Step 3: single-secret mode writes bare hex
	single := SingleSecret(v.SecretV2)
	ct, err = single.Encrypt("x")
	if err != nil || IsEnvelope(ct) {
		t.Fatalf("single encrypt: %q %v", ct, err)
	}
	if got, err := single.Decrypt(ct); err != nil || got != "x" {
		t.Fatalf("single decrypt: %q %v", got, err)
	}
	if _, err := (SecretKeys{}).Encrypt("x"); err == nil {
		t.Fatal("no secret must fail")
	}
}

func TestDecodeJWEFromTypeScript(t *testing.T) {
	v := loadRotationVectors(t)
	keys := keysV2(v)
	// Step 1: tokens encrypted with v2 (current), v1 (older) and the legacy secret all decode, by kid
	for name, tok := range map[string]string{"v2": v.JWESessionV2, "v1": v.JWESessionV1, "legacy": v.JWESessionLegacy} {
		claims, err := keys.DecodeJWE(tok, JWESaltSession)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got struct {
			Session struct {
				Token string `json:"token"`
			} `json:"session"`
			User struct {
				Name string `json:"name"`
			} `json:"user"`
			Version string `json:"version"`
			Exp     int64  `json:"exp"`
			Jti     string `json:"jti"`
		}
		if err := json.Unmarshal(claims, &got); err != nil {
			t.Fatal(err)
		}
		if got.Session.Token != "tok_1" || got.User.Name != "Ann <A&B>" || got.Version != "1" || got.Exp == 0 || got.Jti == "" {
			t.Fatalf("%s claims: %s", name, claims)
		}
	}
	// Step 2: the account cookie salt
	claims, err := keys.DecodeJWE(v.JWEAccountV2, JWESaltAccount)
	if err != nil || !strings.Contains(string(claims), `"accessToken":"gho_access"`) {
		t.Fatalf("account: %s %v", claims, err)
	}
	// Step 3: the wrong salt, a retired secret, an expired token and garbage fail
	if _, err := keys.DecodeJWE(v.JWESessionV2, JWESaltAccount); err == nil {
		t.Fatal("wrong salt must fail")
	}
	onlyV2 := SecretKeys{Current: 2, Keys: map[int]string{2: v.SecretV2}}
	if _, err := onlyV2.DecodeJWE(v.JWESessionV1, JWESaltSession); err == nil {
		t.Fatal("retired secret must fail")
	}
	if _, err := keys.DecodeJWE(v.JWEExpired, JWESaltSession); err == nil {
		t.Fatal("expired token must fail")
	}
	for _, bad := range []string{"", "a.b.c", "a..b.c.d", v.JWESessionV2[:len(v.JWESessionV2)-4] + "AAAA"} {
		if _, err := keys.DecodeJWE(bad, JWESaltSession); err == nil {
			t.Fatalf("garbage %q must fail", bad)
		}
	}
}

func TestMarshalJSONMatchesJSONStringify(t *testing.T) {
	bs, ls := string(rune(92)), string(rune(0x2028))
	got, err := MarshalJSON(map[string]any{"a": "<b> & " + bs + "u003c" + ls})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":"<b> & ` + bs + bs + "u003c" + ls + `"}`; string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestEncodeJWERoundTripAndRotation(t *testing.T) {
	v := loadRotationVectors(t)
	// Step 1: written with v1 as current secret
	old := SecretKeys{Current: 1, Keys: map[int]string{1: v.SecretV1}}
	tok, err := old.EncodeJWE(map[string]any{"a": "<b>"}, JWESaltSession, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Step 2: the header carries alg/enc/kid like jose
	hdr, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if !strings.HasPrefix(string(hdr), `{"alg":"dir","enc":"A256CBC-HS512","kid":"`) {
		t.Fatalf("header %s", hdr)
	}
	// Step 3: after rotating to v2 (v1 kept) it still decodes; new tokens use v2
	claims, err := keysV2(v).DecodeJWE(tok, JWESaltSession)
	if err != nil || !strings.Contains(string(claims), `"a":"<b>"`) {
		t.Fatalf("rotated decode: %s %v", claims, err)
	}
	if _, err := (SecretKeys{Current: 3, Keys: map[int]string{3: "other"}}).DecodeJWE(tok, JWESaltSession); err == nil {
		t.Fatal("unrelated secret must fail")
	}
	// Step 4: an empty object payload gets only the standard claims; non-objects are refused
	tok, err = keysV2(v).EncodeJWE(struct{}{}, JWESaltSession, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := keysV2(v).DecodeJWE(tok, JWESaltSession); err != nil || !strings.HasPrefix(string(claims), `{"iat":`) {
		t.Fatalf("empty payload: %s %v", claims, err)
	}
	if _, err := keysV2(v).EncodeJWE([]int{1}, JWESaltSession, time.Minute); err == nil {
		t.Fatal("array payload must fail")
	}
}
