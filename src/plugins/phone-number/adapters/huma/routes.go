package humaphonenumber

import (
	"net/http"
	"strings"
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

// PhoneNumberRateLimit is the plugin's rule for paths starting with /phone-number (60s, 10 requests).
// /sign-in/phone-number gets the global limiter's /sign-in special rule (10s, 3 requests) instead.
var PhoneNumberRateLimit = ratelimit.Rule{Window: 60 * time.Second, Max: 10}

// RateLimitRules are the plugin's rules for goauth's global limiter (better-auth's phone-number `rateLimit`).
func RateLimitRules() []ratelimit.PathRule {
	return []ratelimit.PathRule{{
		PathMatcher: func(path string) bool { return strings.HasPrefix(path, "/phone-number") },
		Window:      PhoneNumberRateLimit.Window,
		Max:         PhoneNumberRateLimit.Max,
	}}
}

// RegisterRoutes mounts the phone-number endpoints under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"phone-number"}
	route := func(id, path, summary string) pluginkit.Route {
		return pluginkit.Route{
			OperationID: id, Method: http.MethodPost, Path: path, Summary: summary, Tags: tags,
			Access: pluginkit.Public,
		}
	}
	pluginkit.Register(kit, api, route(OpSignInPhoneNumber, SignInPath, "Sign in with phone number"), h.SignIn)
	pluginkit.Register(kit, api, route(OpSendPhoneNumberOTP, "/phone-number/send-otp", "Send OTP to phone number"), h.SendOTP)
	pluginkit.Register(kit, api, route(OpVerifyPhoneNumber, "/phone-number/verify", "Verify phone number"), h.Verify)
	pluginkit.Register(kit, api, route(OpRequestPasswordResetPhoneNumber, "/phone-number/request-password-reset", "Request OTP for password reset via phone number"), h.RequestPasswordReset)
	pluginkit.Register(kit, api, route(OpResetPasswordPhoneNumber, "/phone-number/reset-password", "Reset password using phone number OTP"), h.ResetPassword)
}
