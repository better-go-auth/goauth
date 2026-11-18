package authcrypto

import (
	"context"

	"github.com/better-go-auth/goauth/src/config"
)

// BeforeHashFunc runs before a new password is hashed with HashContext, like a better-auth plugin wrapping
// ctx.password.hash (e.g. have-i-been-pwned). A returned error aborts the hash and is returned unchanged.
type BeforeHashFunc func(ctx context.Context, password string) error

// Passwords hashes and verifies user passwords according to the auth configuration.
// A nil *Passwords behaves with default Better Auth settings (scrypt hashing, all formats verified).
type Passwords struct {
	custom *config.PasswordHasher
	format string
	rehash bool
	// beforeHash runs in HashContext before the password is hashed (nil = nothing)
	beforeHash BeforeHashFunc
}

// WithBeforeHash returns a copy of p whose HashContext runs fn before hashing (better-auth plugins that
// wrap ctx.password.hash). A nil fn returns p unchanged.
func (p *Passwords) WithBeforeHash(fn BeforeHashFunc) *Passwords {
	if fn == nil {
		return p
	}
	cp := Passwords{format: FormatScrypt}
	if p != nil {
		cp = *p
	}
	cp.beforeHash = fn
	return &cp
}

// HashContext hashes a new password like Hash, after the before-hash hook (WithBeforeHash) accepted it.
// Endpoints hash through it so plugins see the request in ctx (path, headers).
func (p *Passwords) HashContext(ctx context.Context, password string) (string, error) {
	// Step 1: plugins may veto the password (e.g. a compromised password)
	if p != nil && p.beforeHash != nil {
		if err := p.beforeHash(ctx, password); err != nil {
			return "", err
		}
	}
	// Step 2: hash with the configured hasher
	return p.Hash(password)
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
