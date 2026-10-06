package models

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// VerificationPurpose describes what a verification token is used for.
type VerificationPurpose string

const (
	PurposeEmailVerification VerificationPurpose = "email-verification"
	PurposePasswordReset     VerificationPurpose = "password-reset"
	PurposeChangeEmail       VerificationPurpose = "change-email"
	// PurposeTwoFactor         VerificationPurpose = "two-factor"
	// PurposeMagicLink         VerificationPurpose = "magic-link"
)

// IsExpired returns true if the token is past its expiry.
func (v VerificationPurpose) Make(val string) string {
	return fmt.Sprintf("%s:%s", v, val)
}

// Verification is better-auth's `verification` model.
type Verification struct {
	// ===== better-auth fields =====
	Base `mapstructure:",squash" ` // id, createdAt, updatedAt
	// Identifier is "<purpose>:<subject>", e.g. "email-verification:user@example.com"., "password-reset:user@example.com"
	Identifier string    `json:"identifier" gorm:"index:idx_verification_identifier;not null" bun:"identifier,notnull"`
	Value      string    `json:"value"      gorm:"not null"                         bun:"value,notnull"` // hashed token/code
	ExpiresAt  time.Time `json:"expiresAt"  gorm:"not null"                                   bun:"expires_at,notnull"`

	// ===== goauth fields (not in better-auth) =====
	UserID string `json:"userId,omitempty"` // empty for rows written by better-auth
	// CallbackURL is where link-based flows redirect after verification.
	CallbackURL *string `json:"callbackUrl" bun:"callback_url"`
}

// IsExpired returns true if the token is past its expiry.
func (v *Verification) IsExpired() bool {
	return time.Now().After(v.ExpiresAt)
}

// BeforeSave stores ExpiresAt in UTC; SQLite compares timestamps as text, so mixed zones misorder.
func (v *Verification) BeforeSave(*gorm.DB) error {
	v.ExpiresAt = v.ExpiresAt.UTC()
	return nil
}
func (Verification) TableName() string { return TableName(ModelVerification) }
