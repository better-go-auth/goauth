package models

import (
	"fmt"
	"time"

	"github.com/birukbelay/gocmn/src/dtos"
)

type UpsertField string

const (
	UpsertByEmail UpsertField = "email" //always upsert by email(user info, and use that col for both email & pwd, and make user id not unique)
	// UpsertByUserId UpsertField = "user_id"
)

func (u UpsertField) S() string {
	return string(u)
}

type CodePurpose string

const (
	SignupVerification = CodePurpose("SIGNUP_VERIFICATION")
	PasswordReset      = CodePurpose("PASSWORD_RESET")
	ChangeEmail        = CodePurpose("CHANGE_EMAIL")
	TWOFA              = CodePurpose("2FA")
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
	Base        `mapstructure:",squash" `
	UserId      string      `gorm:"not null"`
	Email       string      `gorm:"uniqueIndex;not null"` //this is not user email only, it could also be phone number
	CodeHash    string      `gorm:"not null"`
	Purpose     CodePurpose `gorm:"not null"`
	UpdertField UpsertField `gorm:"default:user_id" json:"-"`

	// Identifier: typically "email:user@example.com" or "phone:+1234567890"
	// or "password-reset:user@example.com"
	Identifier string `json:"identifier"  gorm:"not null;index;size:512"         bun:"identifier,notnull"`
	Value      string `json:"value"       gorm:"not null;type:text"              bun:"value,notnull"` // bcrypt-hashed token/code,

	ExpiresAt time.Time `json:"-" `
	// The URL to redirect to after verification (for link-based flows).
	CallbackURL *string `json:"callbackUrl" gorm:"size:2048" bun:"callback_url"`
}

// IsExpired returns true if the token is past its expiry.
func (v *Verification) IsExpired() bool {
	return time.Now().After(v.ExpiresAt)
}

//=================================   !  Session Model  ============================

// Session will be put on redis,
//
//	make it polymorphism for admin and users
type Session struct {
	Base          `mapstructure:",squash" `
	SessionId     string `gorm:"uniqueIndex;not null" `
	UserId        string `gorm:"not null"`
	HashedRefresh string `gorm:"not null" json:"-"`
	DeviceInfo    string
	DeviceToken   string  `json:"-"`
	CompanyID     *string `json:"-"`
	CompanyRoleID *string `json:"-"`

	//we use when the admin block the user, we dont delete the session, we just blacklist it
	Blacklisted   *bool `gorm:"default:false" json:"-"`
	BlacklistedOn *time.Time
}
type SessionFilter struct {
	CompanyID     string `query:"-"`
	CompanyRoleID string `query:"-"`
	SessionId     string `query:"session_id"`
	UserId        string `query:"user_id"`
	HashedRefresh string `query:"hashed_refresh"`
	Blacklisted   bool   `query:"blacklisted"`
}
type SessionQuery struct {
	dtos.PaginationInput
	Blacklisted bool `query:"blacklisted"`
}
