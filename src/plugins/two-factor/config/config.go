// Package config holds the options of the two-factor plugin (better-auth's TwoFactorOptions).
package config

import (
	"context"
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/models/dtos"
)

// Defaults taken from better-auth v1.6 two-factor plugin.
const (
	DefaultTrustDeviceMaxAge     = 30 * 24 * time.Hour // trustDeviceMaxAge: 2592000s
	DefaultTwoFactorCookieMaxAge = 10 * time.Minute    // twoFactorCookieMaxAge: 600s
	DefaultTOTPDigits            = 6
	DefaultTOTPPeriod            = 30 * time.Second
	DefaultOTPDigits             = 6
	DefaultOTPPeriod             = 3 * time.Minute // otpOptions.period: 3 (minutes)
	DefaultOTPAllowedAttempts    = 5
	DefaultBackupCodeAmount      = 10
	DefaultBackupCodeLength      = 10
)

// Config mirrors better-auth's twoFactor({...}) options.
type Config struct {
	// Issuer shown in authenticator apps (falls back to AuthConfig.AppName).
	Issuer string
	// SkipVerificationOnEnable turns 2FA on directly in /two-factor/enable instead of after the first TOTP check.
	SkipVerificationOnEnable bool
	// AllowPasswordless lets users without a password (social / passkey users) manage 2FA without one.
	AllowPasswordless bool
	// TrustDeviceMaxAge is how long a trusted device skips 2FA (default 30 days).
	TrustDeviceMaxAge time.Duration
	// TwoFactorCookieMaxAge is how long the pending sign-in (two_factor cookie) is valid (default 10 minutes).
	TwoFactorCookieMaxAge time.Duration

	TOTPOptions       TOTPOptions
	OTPOptions        OTPOptions
	BackupCodeOptions BackupCodeOptions
}

// TOTPOptions mirrors better-auth's totpOptions.
type TOTPOptions struct {
	// Digits of the TOTP code (default 6).
	Digits int
	// Period of the TOTP code (default 30s).
	Period time.Duration
	// Disable turns the TOTP endpoints off (they answer 400 TOTP_NOT_CONFIGURED).
	Disable bool
	// AllowPasswordless overrides Config.AllowPasswordless for get-totp-uri.
	AllowPasswordless *bool
}

// SendOTPData is passed to OTPOptions.SendOTP.
type SendOTPData struct {
	User dtos.UserResponse
	OTP  string
}

// SendOTPFunc delivers a two-factor OTP (email, SMS, ...). Errors are logged, never returned to the client.
type SendOTPFunc func(ctx context.Context, data SendOTPData, req *http.Request) error

// StoreMode selects how OTPs / backup codes are stored.
type StoreMode string

const (
	StorePlain     StoreMode = "plain"
	StoreHashed    StoreMode = "hashed"
	StoreEncrypted StoreMode = "encrypted"
	// StoreCustom uses the Hash or Encrypt/Decrypt callbacks.
	StoreCustom StoreMode = "custom"
)

// StoreOTPConfig mirrors better-auth's otpOptions.storeOTP ("plain" | "hashed" | "encrypted" | {hash} | {encrypt, decrypt}).
type StoreOTPConfig struct {
	Mode    StoreMode
	Hash    func(otp string) (string, error)
	Encrypt func(otp string) (string, error)
	Decrypt func(stored string) (string, error)
}

// OTPOptions mirrors better-auth's otpOptions.
type OTPOptions struct {
	// SendOTP enables the OTP method; without it /two-factor/send-otp answers 400 OTP_NOT_CONFIGURED.
	SendOTP SendOTPFunc
	// Period is how long a code is valid (default 3 minutes).
	Period time.Duration
	// Digits of the code (default 6).
	Digits int
	// AllowedAttempts before the code is burned (default 5).
	AllowedAttempts int
	// StoreOTP selects the storage format (default plain).
	StoreOTP StoreOTPConfig
}

// StoreBackupCodesConfig mirrors better-auth's backupCodeOptions.storeBackupCodes ("plain" | "encrypted" | {encrypt, decrypt}).
type StoreBackupCodesConfig struct {
	Mode    StoreMode
	Encrypt func(json string) (string, error)
	Decrypt func(stored string) (string, error)
}

// BackupCodeOptions mirrors better-auth's backupCodeOptions.
type BackupCodeOptions struct {
	// Amount of codes generated (default 10).
	Amount int
	// Length of each code before the dash is inserted (default 10, rendered "xxxxx-xxxxx").
	Length int
	// CustomBackupCodesGenerate replaces the default generator.
	CustomBackupCodesGenerate func() []string
	// StoreBackupCodes selects the storage format (default encrypted).
	StoreBackupCodes StoreBackupCodesConfig
	// AllowPasswordless overrides Config.AllowPasswordless for generate-backup-codes.
	AllowPasswordless *bool
}

// WithDefaults fills unset options with better-auth's defaults.
func (c Config) WithDefaults() Config {
	// Step 1: plugin level durations
	if c.TrustDeviceMaxAge <= 0 {
		c.TrustDeviceMaxAge = DefaultTrustDeviceMaxAge
	}
	if c.TwoFactorCookieMaxAge <= 0 {
		c.TwoFactorCookieMaxAge = DefaultTwoFactorCookieMaxAge
	}
	// Step 2: TOTP
	if c.TOTPOptions.Digits <= 0 {
		c.TOTPOptions.Digits = DefaultTOTPDigits
	}
	if c.TOTPOptions.Period <= 0 {
		c.TOTPOptions.Period = DefaultTOTPPeriod
	}
	// Step 3: OTP
	if c.OTPOptions.Digits <= 0 {
		c.OTPOptions.Digits = DefaultOTPDigits
	}
	if c.OTPOptions.Period <= 0 {
		c.OTPOptions.Period = DefaultOTPPeriod
	}
	if c.OTPOptions.AllowedAttempts <= 0 {
		c.OTPOptions.AllowedAttempts = DefaultOTPAllowedAttempts
	}
	if c.OTPOptions.StoreOTP.Mode == "" {
		c.OTPOptions.StoreOTP.Mode = StorePlain
		if c.OTPOptions.StoreOTP.Hash != nil || c.OTPOptions.StoreOTP.Encrypt != nil {
			c.OTPOptions.StoreOTP.Mode = StoreCustom
		}
	}
	// Step 4: backup codes (better-auth stores them encrypted by default)
	if c.BackupCodeOptions.Amount <= 0 {
		c.BackupCodeOptions.Amount = DefaultBackupCodeAmount
	}
	if c.BackupCodeOptions.Length <= 0 {
		c.BackupCodeOptions.Length = DefaultBackupCodeLength
	}
	if c.BackupCodeOptions.StoreBackupCodes.Mode == "" {
		c.BackupCodeOptions.StoreBackupCodes.Mode = StoreEncrypted
		if c.BackupCodeOptions.StoreBackupCodes.Encrypt != nil {
			c.BackupCodeOptions.StoreBackupCodes.Mode = StoreCustom
		}
	}
	return c
}

// TOTPAllowPasswordless resolves totpOptions.allowPasswordless ?? allowPasswordless.
func (c Config) TOTPAllowPasswordless() bool {
	if c.TOTPOptions.AllowPasswordless != nil {
		return *c.TOTPOptions.AllowPasswordless
	}
	return c.AllowPasswordless
}

// BackupCodesAllowPasswordless resolves backupCodeOptions.allowPasswordless ?? allowPasswordless.
func (c Config) BackupCodesAllowPasswordless() bool {
	if c.BackupCodeOptions.AllowPasswordless != nil {
		return *c.BackupCodeOptions.AllowPasswordless
	}
	return c.AllowPasswordless
}
