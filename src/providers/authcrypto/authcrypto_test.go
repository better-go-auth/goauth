package authcrypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matthewhartstonge/argon2"
)

// vectors were produced by better-auth/crypto (testdata/better_auth_vectors.json).
type vectors struct {
	Secret       string `json:"secret"`
	Password     string `json:"password"`
	PasswordHash string `json:"passwordHash"`
	Plaintext    string `json:"plaintext"`
	Ciphertext   string `json:"ciphertext"`
	JWT          string `json:"jwt"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "better_auth_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestScryptMatchesBetterAuth(t *testing.T) {
	v := loadVectors(t)
	ok, err := VerifyPasswordScrypt(v.PasswordHash, v.Password)
	if err != nil || !ok {
		t.Fatalf("better-auth hash must verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := VerifyPasswordScrypt(v.PasswordHash, "wrong"); ok {
		t.Fatal("wrong password must not verify")
	}

	h, err := HashPasswordScrypt(v.Password)
	if err != nil {
		t.Fatal(err)
	}
	if HashFormat(h) != FormatScrypt {
		t.Fatalf("unexpected format for %q", h)
	}
	if ok, _ := VerifyPassword(h, v.Password); !ok {
		t.Fatal("own scrypt hash must verify")
	}
}

func TestVerifyPasswordLegacyFormats(t *testing.T) {
	b, err := HashPasswordBcrypt("secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	argonCfg := argon2.DefaultConfig()
	a, err := argonCfg.HashEncoded([]byte("secret-pass"))
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]string{"bcrypt": b, "argon2": string(a)} {
		if ok, err := VerifyPassword(h, "secret-pass"); !ok || err != nil {
			t.Errorf("%s: expected match, err=%v", name, err)
		}
		if ok, _ := VerifyPassword(h, "nope"); ok {
			t.Errorf("%s: wrong password matched", name)
		}
	}
	if _, err := VerifyPassword("garbage", "x"); err == nil {
		t.Error("unknown format must error")
	}
}

func TestSymmetricMatchesBetterAuth(t *testing.T) {
	v := loadVectors(t)
	got, err := SymmetricDecrypt(v.Secret, v.Ciphertext)
	if err != nil || got != v.Plaintext {
		t.Fatalf("decrypt better-auth ciphertext: %q, %v", got, err)
	}

	ct, err := SymmetricEncrypt(v.Secret, v.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := SymmetricDecrypt(v.Secret, ct); err != nil || back != v.Plaintext {
		t.Fatalf("round trip: %q, %v", back, err)
	}
	if _, err := SymmetricDecrypt("other-secret", ct); err == nil {
		t.Fatal("wrong secret must fail")
	}
}

func TestSecretKeysEnvelope(t *testing.T) {
	v := loadVectors(t)
	keys := SecretKeys{Current: 2, Keys: map[int]string{1: "old-secret", 2: v.Secret}, Legacy: v.Secret}

	env, err := keys.Encrypt("payload")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(env, "$ba$2$") {
		t.Fatalf("unexpected envelope %q", env)
	}
	if got, err := keys.Decrypt(env); err != nil || got != "payload" {
		t.Fatalf("decrypt envelope: %q, %v", got, err)
	}
	if got, err := keys.Decrypt(v.Ciphertext); err != nil || got != v.Plaintext {
		t.Fatalf("legacy bare-hex: %q, %v", got, err)
	}
	if _, err := (SecretKeys{Current: 1, Keys: map[int]string{1: "x"}}).Decrypt(v.Ciphertext); err == nil {
		t.Fatal("bare-hex without legacy secret must fail")
	}
}

func TestJWTMatchesBetterAuth(t *testing.T) {
	v := loadVectors(t)
	claims, err := VerifyJWT(v.JWT, v.Secret)
	if err != nil || claims["email"] != "a@example.com" {
		t.Fatalf("verify better-auth jwt: %v, %v", claims, err)
	}
	if _, err := VerifyJWT(v.JWT, "other"); err == nil {
		t.Fatal("wrong secret must fail")
	}

	tok, err := SignJWT(map[string]any{"email": "b@example.com"}, v.Secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := VerifyJWT(tok, v.Secret); err != nil || c["email"] != "b@example.com" {
		t.Fatalf("round trip: %v, %v", c, err)
	}
	expired, _ := SignJWT(map[string]any{}, v.Secret, -time.Minute)
	if _, err := VerifyJWT(expired, v.Secret); err == nil {
		t.Fatal("expired token must fail")
	}
}
