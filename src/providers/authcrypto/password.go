// Package authcrypto holds better-auth compatible crypto primitives.
package authcrypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/matthewhartstonge/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

// scrypt parameters used by better-auth (@better-auth/utils/password).
const (
	scryptN      = 16384
	scryptR      = 16
	scryptP      = 1
	scryptKeyLen = 64
	saltBytes    = 16
)

// Hash formats recognised by VerifyPassword.
const (
	FormatScrypt  = "scrypt"
	FormatBcrypt  = "bcrypt"
	FormatArgon2  = "argon2"
	FormatUnknown = ""
)

var ErrInvalidHash = errors.New("authcrypto: invalid password hash")

// HashPasswordScrypt returns "<saltHex>:<keyHex>", byte-compatible with better-auth.
func HashPasswordScrypt(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(salt)
	key, err := scryptKey(password, saltHex)
	if err != nil {
		return "", err
	}
	return saltHex + ":" + hex.EncodeToString(key), nil
}

// VerifyPasswordScrypt checks a better-auth "<saltHex>:<keyHex>" hash.
func VerifyPasswordScrypt(hash, password string) (bool, error) {
	saltHex, keyHex, ok := strings.Cut(hash, ":")
	if !ok || saltHex == "" || keyHex == "" {
		return false, ErrInvalidHash
	}
	key, err := scryptKey(password, saltHex)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(key)), []byte(keyHex)) == 1, nil
}

// better-auth passes the hex salt string itself (not the decoded bytes) to scrypt.
func scryptKey(password, saltHex string) ([]byte, error) {
	return scrypt.Key([]byte(norm.NFKC.String(password)), []byte(saltHex), scryptN, scryptR, scryptP, scryptKeyLen)
}

// HashPasswordBcrypt hashes with bcrypt at the default cost (goauth's legacy format).
func HashPasswordBcrypt(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// HashFormat detects which algorithm produced hash.
func HashFormat(hash string) string {
	switch {
	case strings.HasPrefix(hash, "$2"):
		return FormatBcrypt
	case strings.HasPrefix(hash, "$argon2"):
		return FormatArgon2
	}
	saltHex, keyHex, ok := strings.Cut(hash, ":")
	if ok && len(saltHex) == saltBytes*2 && len(keyHex) == scryptKeyLen*2 && isHex(saltHex) && isHex(keyHex) {
		return FormatScrypt
	}
	return FormatUnknown
}

// VerifyPassword verifies scrypt (better-auth), bcrypt and argon2 (goauth legacy) hashes.
func VerifyPassword(hash, password string) (bool, error) {
	switch HashFormat(hash) {
	case FormatScrypt:
		return VerifyPasswordScrypt(hash, password)
	case FormatBcrypt:
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, nil
	case FormatArgon2:
		ok, err := argon2.VerifyEncoded([]byte(password), []byte(hash))
		return err == nil && ok, nil
	}
	return false, ErrInvalidHash
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
