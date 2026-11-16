// Package dtos holds the request and response bodies of the phone-number plugin (better-auth wire format).
package dtos

import "github.com/better-go-auth/goauth/src/models/dtos"

// SignInPhoneNumberInput is the body of POST /sign-in/phone-number.
type SignInPhoneNumberInput struct {
	PhoneNumber string `json:"phoneNumber" doc:"Phone number to sign in. Eg: \"+1234567890\""`
	Password    string `json:"password" doc:"Password to use for sign in."`
	RememberMe  *bool  `json:"rememberMe,omitempty" doc:"Remember the session. Eg: true"`
}

// SignInPhoneNumberResponse is better-auth's {token, user}.
type SignInPhoneNumberResponse struct {
	Token string            `json:"token"`
	User  dtos.UserResponse `json:"user"`
}

// SendOTPInput is the body of POST /phone-number/send-otp.
type SendOTPInput struct {
	PhoneNumber string `json:"phoneNumber" doc:"Phone number to send OTP. Eg: \"+1234567890\""`
}

// MessageResponse is {"message": "code sent"}.
type MessageResponse struct {
	Message string `json:"message"`
}

// VerifyInput is the body of POST /phone-number/verify. Extra fields are accepted (additional user fields).
type VerifyInput struct {
	PhoneNumber       string `json:"phoneNumber" doc:"Phone number to verify. Eg: \"+1234567890\""`
	Code              string `json:"code" doc:"OTP code. Eg: \"123456\""`
	DisableSession    bool   `json:"disableSession,omitempty" doc:"Disable session creation after verification. Eg: false"`
	UpdatePhoneNumber bool   `json:"updatePhoneNumber,omitempty" doc:"Check if there is a session and update the phone number. Eg: true"`
}

// VerifyResponse is better-auth's {status, token, user}.
type VerifyResponse struct {
	Status bool               `json:"status"`
	Token  *string            `json:"token"`
	User   *dtos.UserResponse `json:"user"`
}

// RequestPasswordResetInput is the body of POST /phone-number/request-password-reset.
type RequestPasswordResetInput struct {
	PhoneNumber string `json:"phoneNumber"`
}

// ResetPasswordInput is the body of POST /phone-number/reset-password.
type ResetPasswordInput struct {
	OTP         string `json:"otp" doc:"The one time password to reset the password. Eg: \"123456\""`
	PhoneNumber string `json:"phoneNumber" doc:"The phone number to the account which intends to reset the password for."`
	NewPassword string `json:"newPassword" doc:"The new password."`
}

// StatusResponse is {"status": true}.
type StatusResponse struct {
	Status bool `json:"status"`
}
