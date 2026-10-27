package authcrypto

import "github.com/better-go-auth/goauth/src/config"

// Passwords hashes and verifies user passwords according to the auth configuration.
// A nil *Passwords behaves with default Better Auth settings (scrypt hashing, all formats verified).
type Passwords struct {
	custom *config.PasswordHasher
	format string
	rehash bool
}

// NewPasswords uses Better Auth's default scrypt hasher, unless a custom hasher is set.
func NewPasswords(conf config.AuthConfig) *Passwords {
	// 1. Default to Better Auth standard password format (scrypt) and inherit rehash setting
	p := &Passwords{format: FormatScrypt, rehash: conf.EmailAndPassword.RehashPasswords}

	// 2. Override with custom password hasher if provided
	if h := conf.EmailAndPassword.Password; h != nil && h.Hash != nil && h.Verify != nil {
		p.custom = h
		p.rehash = false
	}
	return p
}

// Hash hashes a new password.
func (p *Passwords) Hash(password string) (string, error) {
	// 1. Use custom hasher if configured
	if p != nil && p.custom != nil {
		return p.custom.Hash(password)
	}

	// 2. If explicitly configured with bcrypt, hash with bcrypt
	if p != nil && p.format == FormatBcrypt {
		return HashPasswordBcrypt(password)
	}

	// 3. Default to scrypt hashing (Better Auth standard)
	return HashPasswordScrypt(password)
}

// Verify checks password against hash. When rehashing is enabled and hash is in an
// older format, upgraded holds a new hash the caller should persist.
func (p *Passwords) Verify(hash, password string) (ok bool, upgraded string, err error) {
	// 1. Use custom verifier if configured
	if p != nil && p.custom != nil {
		ok, err = p.custom.Verify(hash, password)
		return ok, "", err
	}

	// 2. Verify password across all supported hash formats (scrypt, bcrypt, argon2)
	ok, err = VerifyPassword(hash, password)
	format := FormatScrypt
	if p != nil && p.format != "" {
		format = p.format
	}
	if err != nil || !ok || p == nil || !p.rehash || HashFormat(hash) == format {
		return ok, "", err
	}

	// 3. Rehash to target format if rehash is enabled and password matched
	upgraded, err = p.Hash(password)
	if err != nil {
		return true, "", nil
	}
	return true, upgraded, nil
}
