package config

// BearerConfig holds configuration options for the Bearer plugin.
// RequireSignature defaults to true; enabling it requires HMAC-signed
// bearer tokens (<token>.<signature>) matching Better Auth's signed tokens.
type BearerConfig struct {
	// RequireSignature: if true (default), only signed tokens (<token>.<signature>)
	// will be converted to session cookies. Unsigned tokens will be rejected.
	// Default: true.
	RequireSignature *bool
}

// DefaultConfig returns the default BearerConfig with RequireSignature enabled.
func DefaultConfig() BearerConfig {
	t := true
	return BearerConfig{
		RequireSignature: &t,
	}
}

// RequiresSignature reports whether signed tokens are required (default: true).
func (c BearerConfig) RequiresSignature() bool {
	if c.RequireSignature == nil {
		return true
	}
	return *c.RequireSignature
}
