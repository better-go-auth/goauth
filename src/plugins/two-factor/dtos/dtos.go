// Package dtos holds the request and response bodies of the two-factor endpoints.
package dtos

import "github.com/better-go-auth/goauth/src/models/dtos"

// PasswordInput is the body of /two-factor/disable, /two-factor/get-totp-uri and
// /two-factor/generate-backup-codes (password optional only with allowPasswordless).
type PasswordInput struct {
	Password *string `json:"password,omitempty" doc:"User password"`
}

// EnableInput is the body of /two-factor/enable.
type EnableInput struct {
	Password *string `json:"password,omitempty" doc:"User password"`
	Issuer   *string `json:"issuer,omitempty" doc:"Custom issuer for the TOTP URI"`
}

// VerifyCodeInput is the body of /two-factor/verify-totp and /two-factor/verify-otp.
type VerifyCodeInput struct {
	Code        string `json:"code" doc:"The otp code to verify. Eg: \"012345\""`
	TrustDevice *bool  `json:"trustDevice,omitempty" doc:"If true, the device will be trusted for 30 days"`
}

// SendOTPInput is the (optional) body of /two-factor/send-otp.
type SendOTPInput struct {
	TrustDevice *bool `json:"trustDevice,omitempty" doc:"If true, the device will be trusted for 30 days"`
}

// VerifyBackupCodeInput is the body of /two-factor/verify-backup-code.
type VerifyBackupCodeInput struct {
	Code           string `json:"code" doc:"A backup code to verify"`
	DisableSession *bool  `json:"disableSession,omitempty" doc:"If true, the session cookie will not be set"`
	TrustDevice    *bool  `json:"trustDevice,omitempty" doc:"If true, the device will be trusted for 30 days"`
}

// EnableResponse is {totpURI, backupCodes}.
type EnableResponse struct {
	TotpURI     string   `json:"totpURI"`
	BackupCodes []string `json:"backupCodes"`
}

// TotpURIResponse is {totpURI}.
type TotpURIResponse struct {
	TotpURI string `json:"totpURI"`
}

// StatusResponse is {status}.
type StatusResponse struct {
	Status bool `json:"status"`
}

// BackupCodesResponse is {status, backupCodes}.
type BackupCodesResponse struct {
	Status      bool     `json:"status"`
	BackupCodes []string `json:"backupCodes"`
}

// TokenUserResponse is {token, user}; token is omitted when no session was created (disableSession).
type TokenUserResponse struct {
	Token *string           `json:"token,omitempty"`
	User  dtos.UserResponse `json:"user"`
}

// TwoFactorRedirect is the sign-in challenge {twoFactorRedirect, twoFactorMethods}.
type TwoFactorRedirect struct {
	TwoFactorRedirect bool     `json:"twoFactorRedirect"`
	TwoFactorMethods  []string `json:"twoFactorMethods"`
}
