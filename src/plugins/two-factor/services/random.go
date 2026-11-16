package services

import (
	"crypto/rand"
	"strings"
)

// Alphabets of better-auth's generateRandomString.
const (
	alphaLower = "abcdefghijklmnopqrstuvwxyz"
	alphaUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits09   = "0123456789"
	// defaultAlphabet is better-auth's generateRandomString default ("a-z", "0-9", "A-Z", "-_").
	defaultAlphabet = alphaLower + digits09 + alphaUpper + "-_"
)

// RandomString mirrors @better-auth/utils/random: unbiased rejection sampling over charset.
func RandomString(length int, charset string) string {
	// Step 1: only accept bytes below the largest multiple of the charset size (no modulo bias)
	n := len(charset)
	maxValid := (256 / n) * n
	var b strings.Builder
	buf := make([]byte, length*2)
	idx := len(buf)
	// Step 2: draw random bytes until the string is long enough
	for b.Len() < length {
		if idx >= len(buf) {
			if _, err := rand.Read(buf); err != nil {
				panic("two-factor: crypto/rand failed: " + err.Error())
			}
			idx = 0
		}
		r := int(buf[idx])
		idx++
		if r < maxValid {
			b.WriteByte(charset[r%n])
		}
	}
	return b.String()
}
