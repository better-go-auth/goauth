package models

import (
	"time"

	"github.com/better-go-auth/goauth/src/schema"
)

// ModelJWKS is better-auth's logical model name of the key table.
const ModelJWKS = "jwks"

// JWK represents the database model for stored cryptographic keys.
// Matches Better Auth's jwks schema: id, publicKey, privateKey, createdAt, expiresAt (plus goauth's alg, crv).
//
// The gorm tags describe the table older goauth versions created with GORM AutoMigrate; the plugin now
// stores rows through InitContext.Adapter and the table comes from Schema (same table and columns).
type JWK struct {
	ID         string     `gorm:"primaryKey;size:255" json:"id"`
	PublicKey  string     `gorm:"type:text;not null" json:"publicKey"`
	PrivateKey string     `gorm:"type:text;not null" json:"privateKey"`
	CreatedAt  time.Time  `gorm:"not null" json:"createdAt"`
	ExpiresAt  *time.Time ` json:"expiresAt,omitempty"`
	Alg        string     `gorm:"size:50" json:"alg,omitempty"`
	Crv        string     `gorm:"size:50" json:"crv,omitempty"`
}

// Schema is better-auth's jwt plugin schema (plugins/jwt/schema.ts) plus goauth's alg and crv columns,
// which record the key algorithm (a TypeScript server sharing the table leaves them empty).
func Schema() schema.PluginSchema {
	return schema.PluginSchema{ModelJWKS: schema.Model{Fields: map[string]schema.Field{
		"publicKey":  {Type: schema.String, Required: true},
		"privateKey": {Type: schema.String, Required: true},
		"createdAt":  {Type: schema.Date, Required: true},
		"expiresAt":  {Type: schema.Date},
		// goauth fields
		"alg": {Type: schema.String},
		"crv": {Type: schema.String},
	}}}
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
