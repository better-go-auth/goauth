package humaemailotp

import (
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/common/middleware"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/danielgtaylor/huma/v2"
)

// SetupEmailOTPRoutes registers the Better Auth Email OTP endpoints on huma.API.
func SetupEmailOTPRoutes(api huma.API, handler *EmailOTPHandler, basePath string, mdlWare ...*middleware.AuthMiddleware) {
	if basePath == "" {
		basePath = "/api/auth"
	}
	basePath = strings.TrimSuffix(basePath, "/")

	tags := []string{"email-otp"}

	var authMiddlewares huma.Middlewares
	if len(mdlWare) > 0 && mdlWare[0] != nil {
		authMiddlewares = huma.Middlewares{mdlWare[0].Authenticate()}
	}

	post := func(id, path, summary string, mws ...huma.Middlewares) huma.Operation {
		var joined huma.Middlewares
		for _, m := range mws {
			joined = append(joined, m...)
		}
		return huma.Operation{
			OperationID: id,
			Method:      http.MethodPost,
			Path:        basePath + path,
			Summary:     summary,
			Tags:        tags,
			Metadata:    map[string]any{types.RawBodyMetaKey: true},
			Middlewares: joined,
		}
	}

	huma.Register(api, post("sendVerificationOTP", "/email-otp/send-verification-otp", "Send a verification OTP code to user's email"), handler.SendVerificationOTP)
	huma.Register(api, post("checkVerificationOTP", "/email-otp/check-verification-otp", "Check an OTP code without consuming it"), handler.CheckVerificationOTP)
	huma.Register(api, post("verifyEmailOTP", "/email-otp/verify-email", "Verify email address using an OTP code"), handler.VerifyEmail)
	huma.Register(api, post("signInEmailOTP", "/sign-in/email-otp", "Sign in using email and an OTP code"), handler.SignIn)
	huma.Register(api, post("requestPasswordResetEmailOTP", "/email-otp/request-password-reset", "Request password reset using an OTP code"), handler.RequestPasswordReset)
	huma.Register(api, post("forgetPasswordEmailOTP", "/forget-password/email-otp", "Deprecated alias for requesting password reset using an OTP code"), handler.RequestPasswordReset)
	huma.Register(api, post("resetPasswordOTP", "/email-otp/reset-password", "Reset password using an OTP code"), handler.ResetPassword)
	huma.Register(api, post("requestEmailChangeOTP", "/email-otp/request-email-change", "Request email change using OTP", authMiddlewares), handler.RequestEmailChange)
	huma.Register(api, post("changeEmailOTP", "/email-otp/change-email", "Change email using OTP", authMiddlewares), handler.ChangeEmail)
}
