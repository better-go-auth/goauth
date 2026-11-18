package models

import (
	"time"
)

// JWK represents the database model for stored cryptographic keys.
// Matches Better Auth's jwks schema: id, publicKey, privateKey, createdAt, expiresAt.
type JWK struct {
	ID         string     `gorm:"primaryKey;size:255" json:"id"`
	PublicKey  string     `gorm:"type:text;not null" json:"publicKey"`
	PrivateKey string     `gorm:"type:text;not null" json:"privateKey"`
	CreatedAt  time.Time  `gorm:"not null" json:"createdAt"`
	ExpiresAt  *time.Time ` json:"expiresAt,omitempty"`
	Alg        string     `gorm:"size:50" json:"alg,omitempty"`
	Crv        string     `gorm:"size:50" json:"crv,omitempty"`
}

// JWKKey represents a single public key entry in the JWKS set.
type JWKKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKSResponse is the standard response for GET /jwks.
type JWKSResponse struct {
	Keys []JWKKey `json:"keys"`
}
