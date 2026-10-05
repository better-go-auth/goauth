package authcrypto

import (
	"testing"

	"github.com/better-go-auth/goauth/src/config"
)

func TestPasswordsDefaults(t *testing.T) {
	legacy := NewPasswords(config.AuthConfig{})
	h, _ := legacy.Hash("pw-12345678")
	if HashFormat(h) != FormatBcrypt {
		t.Fatalf("legacy mode must hash with bcrypt, got %q", h)
	}

	compat := NewPasswords(config.AuthConfig{Mode: config.ModeCompat})
	h, _ = compat.Hash("pw-12345678")
	if HashFormat(h) != FormatScrypt {
		t.Fatalf("compat mode must hash with scrypt, got %q", h)
	}

	var nilP *Passwords
	h, _ = nilP.Hash("pw-12345678")
	if ok, _, _ := nilP.Verify(h, "pw-12345678"); !ok || HashFormat(h) != FormatBcrypt {
		t.Fatal("nil Passwords must behave like legacy")
	}
}

func TestPasswordsRehash(t *testing.T) {
	bcryptHash, _ := HashPasswordBcrypt("pw-12345678")

	noRehash := NewPasswords(config.AuthConfig{Mode: config.ModeCompat})
	if ok, up, _ := noRehash.Verify(bcryptHash, "pw-12345678"); !ok || up != "" {
		t.Fatalf("rehash must be opt-in: ok=%v up=%q", ok, up)
	}

	p := NewPasswords(config.AuthConfig{Mode: config.ModeCompat,
		EmailAndPassword: config.EmailAndPassword{RehashPasswords: true}})
	ok, up, err := p.Verify(bcryptHash, "pw-12345678")
	if !ok || err != nil || HashFormat(up) != FormatScrypt {
		t.Fatalf("expected scrypt upgrade: ok=%v up=%q err=%v", ok, up, err)
	}
	if ok, up, _ := p.Verify(up, "pw-12345678"); !ok || up != "" {
		t.Fatal("hash already in target format must not be upgraded again")
	}
	if ok, up, _ := p.Verify(bcryptHash, "wrong"); ok || up != "" {
		t.Fatal("wrong password must not upgrade")
	}
}

func TestPasswordsCustom(t *testing.T) {
	p := NewPasswords(config.AuthConfig{EmailAndPassword: config.EmailAndPassword{
		RehashPasswords: true,
		Password: &config.PasswordHasher{
			Hash:   func(pw string) (string, error) { return "custom:" + pw, nil },
			Verify: func(hash, pw string) (bool, error) { return hash == "custom:"+pw, nil },
		},
	}})
	h, _ := p.Hash("x")
	if h != "custom:x" {
		t.Fatalf("custom hash not used: %q", h)
	}
	if ok, up, _ := p.Verify(h, "x"); !ok || up != "" {
		t.Fatal("custom verify must be used without rehash")
	}
}
