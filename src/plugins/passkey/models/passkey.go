// Package models holds the passkey plugin's database model (better-auth's `passkey` table).
package models

import "time"

// Passkey is better-auth's `passkey` model. The struct name maps to the "passkey" table through
// gormutil's naming strategy; JSON names match better-auth's field names.
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
