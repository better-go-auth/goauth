package models

import (
	"time"

	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/birukbelay/gocmn/src/dtos"
)

type RegisterClientInput struct {
	FirstName string `json:"fName" binding:"required,min=2" `
	LastName  string `json:"lName" `
	Email     string `json:"email" binding:"required,email" `
	Password  string `json:"password" binding:"required,min=6"`
	Avatar    string `json:"avatar,omitempty" `
	Country   string `json:"country,omitempty"`
}

// this is for when the admin manually creates the user
type AdminRegisterUsersInput struct {
	FirstName string     `json:"fName" binding:"required,min=2" `
	LastName  string     `json:"lName" `
	Email     string     `json:"email" binding:"required,email" `
	Role      enums.Role `default:"RESPONDER" json:"role" enum:"OPERATOR,RESPONDER,CLIENT"`
	Avatar    string     `json:"avatar,omitempty" `
}

// ProfileUpdateDto This is Used for creating and updating the user
type ProfileUpdateDto struct {
	FirstName string `json:"first_name,omitempty" minLength:"1"`
	LastName  string `json:"last_name,omitempty" `
	// Email     string `json:"email,omitempty" format:"email"`
	Avatar string `json:"avatar,omitempty" `
}

// PasswordUpdateDto This is Used for creating and updating the user
type PasswordUpdateDto struct {
	OldPassword string `json:"old_password,omitempty" minLength:"6"`
	NewPassword string `json:"new_password,omitempty" minLength:"6"`
}

type UpsertField string

const (
	UpsertByEmail UpsertField = "email" //always upsert by email(user info, and use that col for both email & pwd, and make user id not unique)
	// UpsertByUserId UpsertField = "user_id"
)

func (u UpsertField) S() string {
	return string(u)
}

type VerificationCode struct {
	Base        `mapstructure:",squash" `
	UserId      string      `gorm:"not null"`
	Email       string      `gorm:"uniqueIndex;not null"` //this is not user email only, it could also be phone number
	CodeHash    string      `gorm:"not null"`
	Purpose     CodePurpose `gorm:"not null"`
	ExpiresAt   *time.Time  `json:"-" `
	UpdertField UpsertField `gorm:"default:user_id" json:"-"`
}

//=================================   !  CompanyStatus  ============================

type CodePurpose string

const (
	SignupVerification = CodePurpose("SIGNUP_VERIFICATION")
	PasswordReset      = CodePurpose("PASSWORD_RESET")
	ChangeEmail        = CodePurpose("CHANGE_EMAIL")
	TWOFA              = CodePurpose("2FA")
)

type ChangeEmailReqDto struct {
	Password string `json:"password" minLength:"6"`
	NewEmail string `json:"new_email,omitempty" minLength:"6"`
}

type VerifyEmailDto struct {
	Code string `json:"code" `
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
