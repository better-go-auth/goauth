package config

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// Store identifier modes (better-auth's StoreIdentifierOption).
const (
	StoreIdentifierPlain  = "plain"
	StoreIdentifierHashed = "hashed"
)

// StoreIdentifierOption is one better-auth StoreIdentifierOption: "plain", "hashed" or {hash: fn}.
type StoreIdentifierOption struct {
	// Mode is "plain" (default) or "hashed". It is ignored when Hash is set.
	Mode string
	// Hash is a custom identifier hasher (better-auth's {hash: (identifier) => Promise<string>}).
	Hash func(identifier string) (string, error)
}

// IsPlain reports whether identifiers are stored as they are.
func (o StoreIdentifierOption) IsPlain() bool {
	return o.Hash == nil && (o.Mode == "" || o.Mode == StoreIdentifierPlain)
}

// Process is better-auth's processIdentifier: the identifier as it is stored in the verification table.
func (o StoreIdentifierOption) Process(identifier string) (string, error) {
	switch {
	case o.Hash != nil:
		return o.Hash(identifier)
	case o.Mode == StoreIdentifierHashed:
		return HashIdentifier(identifier), nil
	default:
		return identifier, nil
	}
}

// HashIdentifier is better-auth's defaultKeyHasher: SHA-256, unpadded base64url.
func HashIdentifier(identifier string) string {
	sum := sha256.Sum256([]byte(identifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// IdentifierOption is better-auth's getStorageOption: the override whose prefix matches identifier (the longest
// one), else StoreIdentifier.
func (v VerificationOptions) IdentifierOption(identifier string) StoreIdentifierOption {
	best, bestLen := v.StoreIdentifier, -1
	for prefix, opt := range v.StoreIdentifierOverrides {
		if strings.HasPrefix(identifier, prefix) && len(prefix) > bestLen {
			best, bestLen = opt, len(prefix)
		}
	}
	return best
}

// HashesIdentifiers reports whether any identifier may be stored hashed.
func (v VerificationOptions) HashesIdentifiers() bool {
	if !v.StoreIdentifier.IsPlain() {
		return true
	}
	for _, o := range v.StoreIdentifierOverrides {
		if !o.IsPlain() {
			return true
		}
	}
	return false
}
