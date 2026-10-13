package humaemailotp

import (
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/danielgtaylor/huma/v2"
)

// SetupEmailOTPRoutes registers the Better Auth Email OTP endpoints on huma.API.
func SetupEmailOTPRoutes(api huma.API, handler *EmailOTPHandler, basePath string) {
	if basePath == "" {
		basePath = "/api/auth"
	}
	basePath = strings.TrimSuffix(basePath, "/")

	tags := []string{"email-otp"}

	post := func(id, path, summary string) huma.Operation {
		return huma.Operation{
			OperationID: id,
			Method:      http.MethodPost,
			Path:        basePath + path,
			Summary:     summary,
			Tags:        tags,
			Metadata:    map[string]any{types.RawBodyMetaKey: true},
		}
	}

	huma.Register(api, post("sendVerificationOTP", "/email-otp/send-verification-otp", "Send a verification OTP code to user's email"), handler.SendVerificationOTP)
	huma.Register(api, post("checkVerificationOTP", "/email-otp/check-verification-otp", "Check an OTP code without consuming it"), handler.CheckVerificationOTP)
	huma.Register(api, post("verifyEmailOTP", "/email-otp/verify-email", "Verify email address using an OTP code"), handler.VerifyEmail)
	huma.Register(api, post("signInEmailOTP", "/sign-in/email-otp", "Sign in using email and an OTP code"), handler.SignIn)
	huma.Register(api, post("resetPasswordOTP", "/email-otp/reset-password", "Reset password using an OTP code"), handler.ResetPassword)
	huma.Register(api, post("requestEmailChangeOTP", "/email-otp/request-email-change", "Request email change using OTP"), handler.RequestEmailChange)
	huma.Register(api, post("changeEmailOTP", "/email-otp/change-email", "Change email using OTP"), handler.ChangeEmail)
}
