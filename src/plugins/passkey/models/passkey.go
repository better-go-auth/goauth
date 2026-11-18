// Package models holds the passkey plugin's database model (better-auth's `passkey` table).
package models

import (
	"time"

	"github.com/better-go-auth/goauth/src/schema"
)

// ModelPasskey is better-auth's logical model name of the passkey table.
const ModelPasskey = "passkey"

// Passkey is better-auth's `passkey` model; JSON names match better-auth's field names.
//
// The gorm tags describe the table older goauth versions created with GORM AutoMigrate; the plugin now
// stores rows through InitContext.Adapter and the table comes from Schema (same table and columns).
type Passkey struct {
	ID   string  `gorm:"primaryKey;size:255" json:"id"`
	Name *string ` json:"name"`
	// PublicKey is the standard base64 encoding of the COSE credential public key (as @simplewebauthn stores it).
	PublicKey string `gorm:"type:text;not null" json:"publicKey"`
	UserID    string `gorm:"not null;index;size:255" json:"userId"`
	// CredentialID is the base64url (unpadded) credential ID.
	CredentialID string `gorm:"not null;index;size:1024" json:"credentialID"`
	Counter      int64  `gorm:"not null;default:0" json:"counter"`
	// DeviceType is "singleDevice" or "multiDevice".
	DeviceType string `gorm:"not null;size:32" json:"deviceType"`
	BackedUp   bool   `gorm:"not null;default:false" json:"backedUp"`
	// Transports is the comma separated list of authenticator transports ("internal,hybrid").
	Transports *string    ` json:"transports"`
	CreatedAt  *time.Time ` json:"createdAt"`
	AAGUID     *string    `gorm:"size:64;column:aaguid" json:"aaguid"`
}

// Schema is @better-auth/passkey's plugin schema (src/schema.ts, version 1.6.16).
func Schema() schema.PluginSchema {
	return schema.PluginSchema{ModelPasskey: schema.Model{Fields: map[string]schema.Field{
		"name":      {Type: schema.String},
		"publicKey": {Type: schema.String, Required: true},
		"userId": {Type: schema.String, Required: true, Index: true,
			References: &schema.Reference{Model: schema.ModelUser, Field: "id"}},
		"credentialID": {Type: schema.String, Required: true, Index: true},
		"counter":      {Type: schema.Number, Required: true},
		"deviceType":   {Type: schema.String, Required: true},
		"backedUp":     {Type: schema.Boolean, Required: true},
		"transports":   {Type: schema.String},
		"createdAt":    {Type: schema.Date},
		"aaguid":       {Type: schema.String},
	}}}
}
