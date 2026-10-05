package authcrypto

import "github.com/better-go-auth/goauth/src/config"

// Passwords hashes and verifies user passwords according to the auth configuration.
// A nil *Passwords behaves like legacy goauth (bcrypt hashing, all formats verified).
type Passwords struct {
	custom *config.PasswordHasher
	format string
	rehash bool
}

// NewPasswords picks scrypt in compat mode and bcrypt in legacy mode, unless a custom hasher is set.
func NewPasswords(conf config.AuthConfig) *Passwords {
	p := &Passwords{format: FormatBcrypt, rehash: conf.EmailAndPassword.RehashPasswords}
	if conf.Mode == config.ModeCompat {
		p.format = FormatScrypt
	}
	if h := conf.EmailAndPassword.Password; h != nil && h.Hash != nil && h.Verify != nil {
		p.custom = h
		p.rehash = false
	}
	return p
}

// Hash hashes a new password.
func (p *Passwords) Hash(password string) (string, error) {
	if p != nil && p.custom != nil {
		return p.custom.Hash(password)
	}
	if p != nil && p.format == FormatScrypt {
		return HashPasswordScrypt(password)
	}
	return HashPasswordBcrypt(password)
}

// Verify checks password against hash. When rehashing is enabled and hash is in an
// older format, upgraded holds a new hash the caller should persist.
func (p *Passwords) Verify(hash, password string) (ok bool, upgraded string, err error) {
	if p != nil && p.custom != nil {
		ok, err = p.custom.Verify(hash, password)
		return ok, "", err
	}
	ok, err = VerifyPassword(hash, password)
	if err != nil || !ok || p == nil || !p.rehash || HashFormat(hash) == p.format {
		return ok, "", err
	}
	upgraded, err = p.Hash(password)
	if err != nil {
		return true, "", nil
	}
	return true, upgraded, nil
}
