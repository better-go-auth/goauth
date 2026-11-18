package huma

import (
	"net/http"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/danielgtaylor/huma/v2"
)

// RateLimit is better-auth's two-factor rule for every /two-factor/* path: 3 requests per 10 seconds.
var RateLimit = ratelimit.Rule{Window: 10 * time.Second, Max: 3}

// RateLimitRules are the plugin's rules for goauth's global limiter (better-auth's two-factor `rateLimit`).
func RateLimitRules() []ratelimit.PathRule {
	return []ratelimit.PathRule{{
		PathMatcher: func(path string) bool { return strings.HasPrefix(path, "/two-factor/") },
		Window:      RateLimit.Window,
		Max:         RateLimit.Max,
	}}
}

// Register mounts the eight two-factor endpoints.
func Register(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"two-factor"}
	route := func(id, path, summary string, access pluginkit.Access) pluginkit.Route {
		return pluginkit.Route{
			OperationID: id, Method: http.MethodPost, Path: path, Summary: summary, Tags: tags,
			Access: access,
		}
	}
	pluginkit.Register(kit, api, route("enableTwoFactor", "/two-factor/enable", "Enable two factor authentication", pluginkit.Session), h.Enable)
	pluginkit.Register(kit, api, route("disableTwoFactor", "/two-factor/disable", "Disable two factor authentication", pluginkit.FreshSession), h.Disable)
	pluginkit.Register(kit, api, route("getTOTPURI", "/two-factor/get-totp-uri", "Get TOTP URI", pluginkit.Session), h.GetTOTPURI)
	pluginkit.Register(kit, api, route("verifyTOTP", "/two-factor/verify-totp", "Verify two factor TOTP", pluginkit.OptionalSession), h.VerifyTOTP)
	pluginkit.Register(kit, api, route("sendTwoFactorOTP", "/two-factor/send-otp", "Send two factor OTP", pluginkit.OptionalSession), h.SendOTP)
	pluginkit.Register(kit, api, route("verifyTwoFactorOTP", "/two-factor/verify-otp", "Verify two factor OTP", pluginkit.OptionalSession), h.VerifyOTP)
	pluginkit.Register(kit, api, route("generateBackupCodes", "/two-factor/generate-backup-codes", "Generate new backup codes", pluginkit.Session), h.GenerateBackupCodes)
	pluginkit.Register(kit, api, route("verifyBackupCode", "/two-factor/verify-backup-code", "Verify a backup code", pluginkit.OptionalSession), h.VerifyBackupCode)
}
