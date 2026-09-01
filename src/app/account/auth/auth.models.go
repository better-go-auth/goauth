package auth

// VerificationInput is for verifying registration email
type VerificationInput struct {
	Info       string  `json:"info" validate:"required"`
	Code       string  ` json:"code" validate:"required" `
	InviteCode *string `json:"invite_code,omitempty" `
}

// LoginData defines user login form struct
type LoginData struct {
	LoginInfo   string ` json:"info" binding:"required"`
	Password    string ` json:"password" binding:"required"`
	InfoType    string `json:"-" `
	DeviceToken string `json:"device_token,omitempty"`
}

type RefreshTokenInput struct {
	Token string `json:"token"`
}

type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenResponse struct {
	AuthTokens AuthTokens `json:"auth_tokens"`
	UserData   any        `json:"user_data"`
}

// =========================. password reset related

type VerifyReqInput struct {
	Email string `json:"email" binding:"required,email" gorm:"unique"`
}

// PwdResetInput defines user password reset form struct
type PwdResetInput struct {
	NewPassword string `json:"new_password"  binding:"required"`
	Code        string `json:"code"  binding:"required"`
	Info        string `json:"info"`
}

type ChangeActiveCompanyInput struct {
	CompanyID string `json:"company_id" validate:"required"`
}
