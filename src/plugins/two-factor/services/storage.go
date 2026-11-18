package services

import (
	"crypto/subtle"
	"encoding/json"

	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// ─── Backup codes ────────────────────────────────────────────────────────────

// GenerateBackupCodeList mirrors better-auth's generateBackupCodesFn: `amount` codes of `length` chars
// from a-z0-9A-Z, rendered "xxxxx-xxxxx".
func GenerateBackupCodeList(opts tfconfig.BackupCodeOptions) []string {
	// Step 1: a custom generator replaces the default one
	if opts.CustomBackupCodesGenerate != nil {
		return opts.CustomBackupCodesGenerate()
	}
	// Step 2: random codes with a dash after the fifth character
	codes := make([]string, opts.Amount)
	for i := range codes {
		code := RandomString(opts.Length, alphaLower+digits09+alphaUpper)
		if len(code) > 5 {
			code = code[:5] + "-" + code[5:]
		} else {
			code += "-"
		}
		codes[i] = code
	}
	return codes
}

// EncodeBackupCodes serialises codes as JSON and stores them per storeBackupCodes.
func EncodeBackupCodes(codes []string, keys authcrypto.SecretKeys, opts tfconfig.BackupCodeOptions) (string, error) {
	// Step 1: JSON.stringify(codes)
	if codes == nil {
		codes = []string{}
	}
	raw, err := json.Marshal(codes)
	if err != nil {
		return "", err
	}
	// Step 2: encrypt / custom-encrypt / plain
	store := opts.StoreBackupCodes
	switch {
	case store.Mode == tfconfig.StoreEncrypted:
		return keys.Encrypt(string(raw))
	case store.Encrypt != nil:
		return store.Encrypt(string(raw))
	default:
		return string(raw), nil
	}
}

// DecodeBackupCodes reverses EncodeBackupCodes (nil when the stored value cannot be read, like safeJSONParse).
func DecodeBackupCodes(stored string, keys authcrypto.SecretKeys, opts tfconfig.BackupCodeOptions) []string {
	// Step 1: decrypt when needed
	store := opts.StoreBackupCodes
	plain := stored
	var err error
	switch {
	case store.Mode == tfconfig.StoreEncrypted:
		plain, err = keys.Decrypt(stored)
	case store.Decrypt != nil:
		plain, err = store.Decrypt(stored)
	}
	if err != nil {
		return nil
	}
	// Step 2: parse the JSON array
	var codes []string
	if json.Unmarshal([]byte(plain), &codes) != nil {
		return nil
	}
	return codes
}

// ─── OTP storage ─────────────────────────────────────────────────────────────

// StoreOTP converts a fresh code into its stored form (better-auth's storeOTP).
func StoreOTP(otp string, keys authcrypto.SecretKeys, cfg tfconfig.StoreOTPConfig) (string, error) {
	switch {
	case cfg.Mode == tfconfig.StoreHashed:
		return HashOTP(otp), nil
	case cfg.Hash != nil:
		return cfg.Hash(otp)
	case cfg.Encrypt != nil:
		return cfg.Encrypt(otp)
	case cfg.Mode == tfconfig.StoreEncrypted:
		return keys.Encrypt(otp)
	default:
		return otp, nil
	}
}

// OTPMatches compares the user input with the stored code (better-auth's decryptOrHashForComparison
// followed by a constant-time comparison).
func OTPMatches(stored, input string, keys authcrypto.SecretKeys, cfg tfconfig.StoreOTPConfig) bool {
	// Step 1: bring both sides to the same form
	left, right := stored, input
	var err error
	switch {
	case cfg.Mode == tfconfig.StoreHashed:
		right = HashOTP(input)
	case cfg.Mode == tfconfig.StoreEncrypted:
		left, err = keys.Decrypt(stored)
	case cfg.Hash != nil:
		right, err = cfg.Hash(input)
	case cfg.Decrypt != nil:
		left, err = cfg.Decrypt(stored)
	}
	if err != nil {
		return false
	}
	// Step 2: constant-time compare
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
