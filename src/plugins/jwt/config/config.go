package config

import (
	"fmt"
	"time"
)

// Signing algorithms supported for JWKS key pairs (better-auth's keyPairConfig.alg values).
const (
	AlgEdDSA = "EdDSA" // Ed25519 (default)
	AlgES256 = "ES256" // ECDSA P-256 + SHA-256
	AlgES512 = "ES512" // ECDSA P-521 + SHA-512
	AlgPS256 = "PS256" // RSA-PSS + SHA-256
	AlgRS256 = "RS256" // RSASSA-PKCS1-v1_5 + SHA-256
)

// Curves used by the supported algorithms.
const (
	CrvEd25519 = "Ed25519"
	CrvP256    = "P-256"
	CrvP521    = "P-521"
)

// DefaultRSAModulusLength is the RSA key size (bits) used for PS256 / RS256 when ModulusLength is 0.
const DefaultRSAModulusLength = 2048

// KeyPairConfig defines the cryptographic algorithm and curve for JWKS keys.
type KeyPairConfig struct {
	Alg string `json:"alg,omitempty"` // default "EdDSA"
	Crv string `json:"crv,omitempty"` // default "Ed25519"
	// ModulusLength is the RSA key size in bits for PS256 / RS256 (default 2048, minimum 2048).
	ModulusLength int `json:"modulusLength,omitempty"`
}

// Normalize validates the key pair configuration and fills in its defaults: Alg defaults to EdDSA,
// Crv is derived from Alg (Ed25519, P-256 for ES256, P-521 for ES512, none for RSA) and ModulusLength
// defaults to 2048 for RSA. It returns an error for algorithms that cannot sign JWTs (ECDH-ES) or that
// are not supported, and for a Crv that does not match Alg.
func (k KeyPairConfig) Normalize() (KeyPairConfig, error) {
	// Step 1: default algorithm
	if k.Alg == "" {
		k.Alg = AlgEdDSA
	}

	// Step 2: derive / check the curve and RSA modulus for the algorithm
	switch k.Alg {
	case AlgEdDSA:
		return k.withCurve(CrvEd25519)
	case AlgES256:
		return k.withCurve(CrvP256)
	case AlgES512:
		return k.withCurve(CrvP521)
	case AlgPS256, AlgRS256, "RSA256":
		// better-auth's types spell RS256 as "RSA256"; accept both
		if k.Alg == "RSA256" {
			k.Alg = AlgRS256
		}
		k.Crv = ""
		if k.ModulusLength == 0 {
			k.ModulusLength = DefaultRSAModulusLength
		}
		if k.ModulusLength < DefaultRSAModulusLength {
			return k, fmt.Errorf("jwt: keyPairConfig.modulusLength must be at least %d bits, got %d", DefaultRSAModulusLength, k.ModulusLength)
		}
		return k, nil
	case "ECDH-ES":
		return k, fmt.Errorf("jwt: keyPairConfig.alg %q is a key-agreement algorithm and cannot sign JWTs; use EdDSA, ES256, ES512, PS256 or RS256", k.Alg)
	default:
		return k, fmt.Errorf("jwt: unsupported keyPairConfig.alg %q; supported: EdDSA, ES256, ES512, PS256, RS256", k.Alg)
	}
}

// withCurve sets Crv to want when it is empty, and rejects any other curve.
func (k KeyPairConfig) withCurve(want string) (KeyPairConfig, error) {
	if k.Crv == "" {
		k.Crv = want
	}
	if k.Crv != want {
		return k, fmt.Errorf("jwt: keyPairConfig.crv %q is not supported with alg %s (use %s)", k.Crv, k.Alg, want)
	}
	k.ModulusLength = 0
	return k, nil
}

// JwksConfig defines options for JWKS storage and endpoints.
type JwksConfig struct {
	// RemoteURL disables the local /jwks endpoint and redirects/points to an external URL.
	RemoteURL string `json:"remoteUrl,omitempty"`
	// KeyPairConfig specifies the key algorithm and curve (default: EdDSA / Ed25519).
	// Supported: EdDSA (Ed25519), ES256 (P-256), ES512 (P-521), PS256 and RS256 (ModulusLength, default 2048).
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
			// Crv is derived from Alg (see KeyPairConfig.Normalize), so changing only Alg works
			KeyPairConfig: KeyPairConfig{
				Alg: AlgEdDSA,
			},
			GracePeriod: 30 * 24 * time.Hour, // 30 days
			JwksPath:    "/jwks",
		},
		JWT: JWTClaimConfig{
			ExpirationTime: 15 * time.Minute,
		},
	}
}
