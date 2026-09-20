// Package token defines the token management interface for better-go-auth.
// Two implementations are provided: opaque session tokens (default) and JWT.
package token

import "context"

// CustomClaims carries the data embedded in a token.
type CustomClaims struct {
	UserID    string `json:"userId"`
	SessionID string `json:"sessionId"`
	Role      string `json:"role"`
	// Org related claims
	ActiveOrgRole string         `json:"activeOrgRole"`
	ActiveOrgId   string         `json:"activeOrgId"`
	Data          map[string]any `json:"data,omitempty"`
	// ExpiresAt as Unix timestamp.
	ExpiresAt int64 `json:"exp"`
}

// ITokenManager manages the creation and validation of auth tokens.
// Swap implementations to change from session-based to JWT-based auth.
type ITokenManager interface {
	// GenerateToken creates a new opaque/signed token string for a session.
	GenerateToken(ctx context.Context, claims CustomClaims) (string, error)
	// ValidateToken validates a token string and returns the embedded claims.
	// Returns an error if the token is invalid, expired, or tampered.
	ValidateToken(ctx context.Context, token string) (*CustomClaims, error)
	// IsJWT returns true if this manager produces/validates JWTs (stateless).
	// When true, the middleware can validate tokens cryptographically without a DB lookup.
	IsJWT() bool
}
