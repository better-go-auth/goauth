package config

// BearerConfig holds configuration options for the Bearer plugin.
// RequireSignature defaults to false for Better Auth compat; enabling it
// requires HMAC-signed bearer tokens and is recommended for production.
type BearerConfig struct {
	// RequireSignature: if true, only signed tokens (<token>.<signature>)
	// will be converted to session cookies. Unsigned tokens will be rejected.
	// Default: false (matches Better Auth default).
	RequireSignature bool
}

// DefaultConfig returns the default BearerConfig.
func DefaultConfig() BearerConfig {
	return BearerConfig{
		RequireSignature: true,
	}
}
