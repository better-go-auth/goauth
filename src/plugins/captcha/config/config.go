// Package config holds the options of the captcha plugin (better-auth's CaptchaOptions).
package config

import (
	"net/http"
	"time"
)

// Provider is a captcha provider (better-auth's Providers).
type Provider string

// The providers better-auth supports.
const (
	CloudflareTurnstile Provider = "cloudflare-turnstile"
	GoogleRecaptcha     Provider = "google-recaptcha"
	HCaptcha            Provider = "hcaptcha"
	CaptchaFox          Provider = "captchafox"
)

// SiteVerifyURLs are the providers' verification endpoints (better-auth's siteVerifyMap).
var SiteVerifyURLs = map[Provider]string{
	CloudflareTurnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	GoogleRecaptcha:     "https://www.google.com/recaptcha/api/siteverify",
	HCaptcha:            "https://api.hcaptcha.com/siteverify",
	CaptchaFox:          "https://api.captchafox.com/siteverify",
}

// DefaultEndpoints are the endpoints protected when Endpoints is empty (better-auth's defaultEndpoints).
var DefaultEndpoints = []string{"/sign-up/email", "/sign-in/email", "/request-password-reset"}

// DefaultMinScore is the reCAPTCHA v3 score threshold (better-auth's minScore default 0.5).
const DefaultMinScore = 0.5

// DefaultHTTPTimeout bounds one verification call to the provider.
const DefaultHTTPTimeout = 30 * time.Second

// CaptchaConfig holds the options of the captcha plugin.
type CaptchaConfig struct {
	// Provider selects the captcha service (required).
	Provider Provider
	// SecretKey is the provider secret sent with every verification (required; a missing key answers
	// 500 UNKNOWN_ERROR on protected endpoints, like better-auth).
	SecretKey string
	// Endpoints are the protected endpoints, matched as substrings of the request path relative to
	// BasePath (default DefaultEndpoints). "/sign-in/email-otp" is exempt unless listed explicitly.
	Endpoints []string
	// SiteVerifyURLOverride replaces the provider's verification URL (self-hosted or test servers).
	SiteVerifyURLOverride string
	// MinScore is the minimum reCAPTCHA v3 score (google-recaptcha only; default 0.5). Responses without a
	// score (v2) only need success.
	MinScore *float64
	// SiteKey is sent as `sitekey` to hCaptcha and CaptchaFox when set.
	SiteKey string
	// HTTPClient performs the verification calls (default: a client with DefaultHTTPTimeout).
	HTTPClient *http.Client
}

// WithDefaults fills unset options with better-auth's defaults.
func (c CaptchaConfig) WithDefaults() CaptchaConfig {
	if len(c.Endpoints) == 0 {
		c.Endpoints = append([]string(nil), DefaultEndpoints...)
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return c
}

// SiteVerifyURL returns SiteVerifyURLOverride or the provider's verification URL.
func (c CaptchaConfig) SiteVerifyURL() string {
	if c.SiteVerifyURLOverride != "" {
		return c.SiteVerifyURLOverride
	}
	return SiteVerifyURLs[c.Provider]
}

// MinScoreOrDefault returns MinScore or DefaultMinScore.
func (c CaptchaConfig) MinScoreOrDefault() float64 {
	if c.MinScore != nil {
		return *c.MinScore
	}
	return DefaultMinScore
}
