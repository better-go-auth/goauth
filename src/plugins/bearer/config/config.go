package config

// BearerConfig holds configuration options for the Bearer plugin.
type BearerConfig struct {
	// RequireSignature: if true, only signed tokens (<token>.<signature>)
	// will be converted to session cookies. Unsigned tokens will be rejected.
	// Default: false (matches Better Auth default).
	RequireSignature bool
}

// DefaultConfig returns the default BearerConfig.
func DefaultConfig() BearerConfig {
	return BearerConfig{
		RequireSignature: false,
	}
}
