package dtos

import (
	"github.com/better-go-auth/goauth/src/models"
)

// VerificationInput is for verifying registration email.
type VerificationInput struct {
	Info       string  `json:"info" validate:"required"`
	Code       string  `json:"code" validate:"required"`
	InviteCode *string `json:"invite_code,omitempty"`
}

// LoginData defines the user login form struct.
type LoginData struct {
	LoginInfo   string `json:"info" binding:"required"`
	Password    string `json:"password" binding:"required"`
	InfoType    string `json:"-"`
	DeviceToken string `json:"device_token,omitempty"`
}

// RefreshTokenInput defines input for token refresh or logout.
type RefreshTokenInput struct {
	Token string `json:"token"`
}

// TokenResponse represents a token issue response with user payload.
type TokenResponse struct {
	AuthTokens *models.AuthTokens `json:"auth_tokens"`
	UserData   models.User        `json:"user_data"`
}

// =========================. password reset related

// VerifyReqInput is used to request password reset code.
type VerifyReqInput struct {
	Email string `json:"email" binding:"required,email" gorm:"unique"`
}

// PwdResetInput defines password reset input.
type PwdResetInput struct {
	NewPassword string `json:"new_password" binding:"required"`
	Code        string `json:"code" binding:"required"`
	Info        string `json:"info"`
}

// ChangeActiveCompanyInput defines input for switching company/organization.
type ChangeActiveCompanyInput struct {
	OrgID     string `json:"org_id,omitempty"`
	CompanyID string `json:"company_id,omitempty"` // Deprecated: use OrgID instead
}
