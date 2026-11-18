// Package models holds the two-factor plugin's table (better-auth's "twoFactor" model).
package models

import (
	"github.com/better-go-auth/goauth/src/schema"
)

// ModelTwoFactor is better-auth's logical model name of the two-factor table.
const ModelTwoFactor = "twoFactor"

// TwoFactor is one user's 2FA secrets (better-auth's twoFactor model).
// Secret is the symmetric-encrypted TOTP secret; BackupCodes is the JSON array of codes, encrypted by default.
//
// The gorm tags describe the table older goauth versions created with GORM AutoMigrate; the plugin now
// stores rows through InitContext.Adapter and the table comes from Schema (same table and columns).
type TwoFactor struct {
	ID          string `gorm:"primaryKey;size:255" json:"id"`
	Secret      string `gorm:"type:text;not null" json:"-"`
	BackupCodes string `gorm:"type:text;not null" json:"-"`
	UserID      string `gorm:"size:255;not null;index" json:"-"`
	// Verified is false until the first TOTP code is checked (better-auth default true for legacy rows).
	Verified bool `gorm:"not null" json:"verified"`
}

// Schema is better-auth's two-factor plugin schema for the twoFactor table (plugins/two-factor/schema.ts).
// The user's twoFactorEnabled field is declared with the core user fields.
//
// better-auth also indexes secret; goauth never looks rows up by secret, and older goauth databases store it
// in a text column, which MySQL can't index, so the index is left out.
func Schema() schema.PluginSchema {
	hidden := schema.Bool(false)
	return schema.PluginSchema{ModelTwoFactor: schema.Model{Fields: map[string]schema.Field{
		"secret":      {Type: schema.String, Required: true, Returned: hidden},
		"backupCodes": {Type: schema.String, Required: true, Returned: hidden},
		"userId": {Type: schema.String, Required: true, Returned: hidden, Index: true,
			References: &schema.Reference{Model: schema.ModelUser, Field: "id", OnDelete: schema.Cascade}},
		"verified": {Type: schema.Boolean, Default: true, Input: schema.Bool(false)},
	}}}
}
