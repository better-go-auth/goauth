// Package idgen generates record IDs and secret tokens.
package idgen

import (
	"crypto/rand"

	"github.com/oklog/ulid/v2"
)

const idAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GenerateID returns a 32-char [a-zA-Z0-9] id, like better-auth's generateId().
// goauth's legacy columns are sized for 26-char ULIDs, so only use it after widening them.
func GenerateID() string {
	return RandomString(32)
}

// GenerateToken returns a 32-char session token, like better-auth's generateId(32).
func GenerateToken() string {
	return RandomString(32)
}

// IsToken reports whether s has the shape of a GenerateToken value (32 chars of [a-zA-Z0-9]).
func IsToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// ULID returns a 26-char sortable id (goauth's default).
func ULID() string {
	return ulid.Make().String()
}

// RandomString returns n characters from [a-zA-Z0-9] using rejection sampling (no modulo bias).
func RandomString(n int) string {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic("idgen: crypto/rand failed: " + err.Error())
		}
		for _, b := range buf {
			// 248 = 4*62, the largest multiple of 62 below 256
			if b < 248 {
				out = append(out, idAlphabet[b%62])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out)
}
