// Package idgen generates record IDs and secret tokens.
package idgen

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
)

const idAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Format names an ID format for config Advanced.Database.IDFormat.
type Format string

const (
	// FormatRandom is better-auth's default: 32 chars of [a-zA-Z0-9] (also used for "").
	FormatRandom Format = "random"
	// FormatUUID is a random RFC 4122 UUID v4 (36 chars), like better-auth's generateId: "uuid".
	FormatUUID Format = "uuid"
	// FormatULID is a 26-char time-sortable ULID (goauth's old default).
	FormatULID Format = "ulid"
)

// ForFormat returns the generator of format f ("" means FormatRandom).
func ForFormat(f Format) (func() string, error) {
	switch Format(strings.ToLower(string(f))) {
	case "", FormatRandom:
		return RandomID, nil
	case FormatUUID:
		return func() string { return uuid.NewString() }, nil
	case FormatULID:
		return ULID, nil
	default:
		return nil, fmt.Errorf("idgen: unknown ID format %q (use random, uuid or ulid)", f)
	}
}

// generator is the process-wide ID generator behind GenerateID (nil = RandomID).
var generator atomic.Pointer[func() string]

// SetGenerator replaces the generator GenerateID uses in the whole process; nil restores the default
// (RandomID). SetupGoAuth calls it with the configured Advanced.Database.GenerateID / IDFormat, so core,
// repositories and every plugin create IDs of the same format.
func SetGenerator(fn func() string) {
	if fn == nil {
		generator.Store(nil)
		return
	}
	generator.Store(&fn)
}

// GenerateID returns a new record ID from the configured generator (default RandomID, like better-auth).
func GenerateID() string {
	if fn := generator.Load(); fn != nil {
		return (*fn)()
	}
	return RandomID()
}

// RandomID returns a 32-char [a-zA-Z0-9] id, like better-auth's generateId().
func RandomID() string {
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

// ULID returns a 26-char sortable id (goauth's old default, now Advanced.Database.IDFormat = "ulid").
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
