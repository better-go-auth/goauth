package humaphonenumber

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpSignInPhoneNumber               = "signInPhoneNumber"
	OpSendPhoneNumberOTP              = "sendPhoneNumberOTP"
	OpVerifyPhoneNumber               = "verifyPhoneNumber"
	OpRequestPasswordResetPhoneNumber = "requestPasswordResetPhoneNumber"
	OpResetPasswordPhoneNumber        = "resetPasswordPhoneNumber"
)

var (
	// PhoneNumberRateLimit is the plugin's rule for paths starting with /phone-number (60s, 10 requests).
	PhoneNumberRateLimit = ratelimit.Rule{Window: 60 * time.Second, Max: 10}
	// SignInRateLimit is better-auth's default special rule for /sign-in/* paths (10s, 3 requests).
	SignInRateLimit = ratelimit.Rule{Window: 10 * time.Second, Max: 3}
)

// RegisterRoutes mounts the phone-number endpoints under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"phone-number"}
	phoneRule, signInRule := PhoneNumberRateLimit, SignInRateLimit
	route := func(id, path, summary string, rule *ratelimit.Rule) pluginkit.Route {
		return pluginkit.Route{
			OperationID: id, Method: http.MethodPost, Path: path, Summary: summary, Tags: tags,
			Access: pluginkit.Public, RateLimit: rule,
		}
	}
	pluginkit.Register(kit, api, route(OpSignInPhoneNumber, SignInPath, "Sign in with phone number", &signInRule), h.SignIn)
	pluginkit.Register(kit, api, route(OpSendPhoneNumberOTP, "/phone-number/send-otp", "Send OTP to phone number", &phoneRule), h.SendOTP)
	pluginkit.Register(kit, api, route(OpVerifyPhoneNumber, "/phone-number/verify", "Verify phone number", &phoneRule), h.Verify)
	pluginkit.Register(kit, api, route(OpRequestPasswordResetPhoneNumber, "/phone-number/request-password-reset", "Request OTP for password reset via phone number", &phoneRule), h.RequestPasswordReset)
	pluginkit.Register(kit, api, route(OpResetPasswordPhoneNumber, "/phone-number/reset-password", "Reset password using phone number OTP", &phoneRule), h.ResetPassword)
}
