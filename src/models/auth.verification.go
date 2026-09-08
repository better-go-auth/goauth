package models

import (
	"fmt"
	"time"
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

type Verification struct {
	Base   `mapstructure:",squash" `
	UserId string `gorm:"not null"`
	// Identifier: typically "email:user@example.com" or "phone:+1234567890"
	// or "password-reset:user@example.com"
	Identifier string `json:"identifier"  gorm:"uniqueIndex;not null"         bun:"identifier,notnull"`
	Value      string `json:"value"       gorm:"not null;type:text"              bun:"value,notnull"` // bcrypt-hashed token/code,

	ExpiresAt time.Time `json:"-" `
	// The URL to redirect to after verification (for link-based flows).
	CallbackURL *string `json:"callbackUrl" gorm:"size:2048" bun:"callback_url"`
}

// IsExpired returns true if the token is past its expiry.
func (v *Verification) IsExpired() bool {
	return time.Now().After(v.ExpiresAt)
}
func (Verification) TableName() string { return "auth_verifications" }
