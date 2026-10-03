package hasher

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// TokenHash hashes a high-entropy token (e.g. a refresh token) for storage.
// A fast hash is enough here; slow KDFs are only needed for low-entropy passwords.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokenMatches compares a token against a stored hash in constant time.
// Hashes created by older versions with argon2 are still accepted.
func TokenMatches(token, storedHash string) bool {
	if strings.HasPrefix(storedHash, "$argon2") {
		return ArgonPasswordsMatch(token, storedHash)
	}
	return subtle.ConstantTimeCompare([]byte(TokenHash(token)), []byte(storedHash)) == 1
}
