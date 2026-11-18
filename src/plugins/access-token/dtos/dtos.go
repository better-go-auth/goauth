package dtos

import (
	"time"

	"github.com/better-go-auth/goauth/src/models/dtos"
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
	AuthTokens *AuthTokens       `json:"auth_tokens"`
	UserData   dtos.UserResponse `json:"user_data"`
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

// ─── Legacy /signup, /login and /refresh types (moved here from the core models package) ─────────────

// RegisterClientInput is the legacy POST /signup body.
// Huma validates the tags below (a 400 VALIDATION_ERROR); the password length bounds come from the core
// EmailAndPassword.MinPasswordLength / MaxPasswordLength config and are checked by AuthService.RegisterWithEmail,
// which also rejects display-name email forms ("Bob <a@b.co>") like core sign-up does.
type RegisterClientInput struct {
	FirstName string `json:"fName" minLength:"2" doc:"First name (also stored as the user's name)"`
	LastName  string `json:"lName,omitempty" doc:"Last name (optional)"`
	Email     string `json:"email" format:"email" doc:"Email address"`
	Password  string `json:"password" minLength:"1" doc:"Password; length bounds follow EmailAndPassword.MinPasswordLength/MaxPasswordLength (default 8..128)"`
	Avatar    string `json:"avatar,omitempty" doc:"Image URL (optional); stored as the user's image"`
	Country   string `json:"country,omitempty"`
}

// AuthTokens is the access/refresh JWT pair the legacy /login and /refresh routes return.
type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// LegacySignInResponse is the legacy /login and /refresh body: better-auth's sign-in response plus the JWT pair.
type LegacySignInResponse struct {
	dtos.SignInResponse
	AuthTokens *AuthTokens `json:"authTokens,omitempty"`
}

// SessionOpt are the options of a legacy access/refresh session.
type SessionOpt struct {
	ClearSession bool
	ActiveOrgID  *string
	OrgRoleID    *string
	OrgRole      *string
	DeviceToken  string
	// ImpersonatedBy marks the session as an admin impersonation.
	ImpersonatedBy *string
	// ExpiresIn overrides the session row lifetime (default: refresh token lifetime).
	ExpiresIn time.Duration
}
