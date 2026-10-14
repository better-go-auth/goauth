package config

import "time"

// KeyPairConfig defines the cryptographic algorithm and curve for JWKS keys.
type KeyPairConfig struct {
	Alg string `json:"alg,omitempty"` // default "EdDSA"
	Crv string `json:"crv,omitempty"` // default "Ed25519"
}

// JwksConfig defines options for JWKS storage and endpoints.
type JwksConfig struct {
	// RemoteURL disables the local /jwks endpoint and redirects/points to an external URL.
	RemoteURL string `json:"remoteUrl,omitempty"`
	// KeyPairConfig specifies the key algorithm and curve (default: EdDSA / Ed25519).
	KeyPairConfig KeyPairConfig `json:"keyPairConfig,omitempty"`
	// DisablePrivateKeyEncryption disables AES/XChaCha encryption of private keys in the database.
	DisablePrivateKeyEncryption bool `json:"disablePrivateKeyEncryption,omitempty"`
	// RotationInterval is how often keys should rotate (0 = disabled).
	RotationInterval time.Duration `json:"rotationInterval,omitempty"`
	// GracePeriod is how long expired keys remain in the JWKS for verification (default: 30 days).
	GracePeriod time.Duration `json:"gracePeriod,omitempty"`
	// JwksPath is the endpoint path exposing JWKS (default: "/jwks").
	JwksPath string `json:"jwksPath,omitempty"`
}

// JWTClaimConfig defines options for JWT token generation and verification.
type JWTClaimConfig struct {
	// Issuer sets the "iss" claim (defaults to baseURL).
	Issuer string `json:"issuer,omitempty"`
	// Audience sets the "aud" claim (defaults to baseURL).
	Audience string `json:"audience,omitempty"`
	// ExpirationTime sets how long generated JWTs are valid (default: 15 minutes).
	ExpirationTime time.Duration `json:"expirationTime,omitempty"`
	// DefinePayload customizes the claims payload from a session.
	DefinePayload func(session any) (map[string]any, error) `json:"-"`
	// GetSubject customizes the "sub" claim (defaults to user.id).
	GetSubject func(session any) (string, error) `json:"-"`
	// Sign provides a custom remote signing function (requires RemoteURL).
	Sign func(payload map[string]any) (string, error) `json:"-"`
}

// JWTConfig holds the full configuration for the JWT plugin.
type JWTConfig struct {
	Jwks                    JwksConfig     `json:"jwks,omitempty"`
	JWT                     JWTClaimConfig `json:"jwt,omitempty"`
	DisableSettingJwtHeader bool           `json:"disableSettingJwtHeader,omitempty"`
}

// DefaultConfig returns the default JWT configuration matching Better Auth.
func DefaultConfig() JWTConfig {
	return JWTConfig{
		Jwks: JwksConfig{
			KeyPairConfig: KeyPairConfig{
				Alg: "EdDSA",
				Crv: "Ed25519",
			},
			GracePeriod: 30 * 24 * time.Hour, // 30 days
			JwksPath:    "/jwks",
		},
		JWT: JWTClaimConfig{
			ExpirationTime: 15 * time.Minute,
		},
	}
}
