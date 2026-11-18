// Package config holds the options of the device-authorization plugin (better-auth's
// DeviceAuthorizationOptions).
package config

import (
	"context"
	"time"
)

// Defaults of better-auth's deviceAuthorizationOptionsSchema.
const (
	// DefaultExpiresIn is the device code lifetime ("30m").
	DefaultExpiresIn = 30 * time.Minute
	// DefaultInterval is the minimum polling interval ("5s").
	DefaultInterval = 5 * time.Second
	// DefaultDeviceCodeLength is the length of generated device codes.
	DefaultDeviceCodeLength = 40
	// DefaultUserCodeLength is the length of generated user codes.
	DefaultUserCodeLength = 8
	// DefaultVerificationURI is the verification page when VerificationURI is empty.
	DefaultVerificationURI = "/device"
)

// UserCodeCharset is better-auth's default user code alphabet: upper-case letters and digits without the
// easily confused I, O, 0 and 1 (32 characters).
const UserCodeCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GenerateCodeFunc returns a new device or user code.
type GenerateCodeFunc func(ctx context.Context) (string, error)

// ValidateClientFunc reports whether clientID is an allowed client (better-auth's validateClient).
type ValidateClientFunc func(ctx context.Context, clientID string) (bool, error)

// DeviceAuthRequestFunc is called for every accepted POST /device/code (better-auth's onDeviceAuthRequest).
// scope is nil when the request has none. A returned error aborts the request (an *autherr.AuthError is
// sent as is, anything else is an internal error).
type DeviceAuthRequestFunc func(ctx context.Context, clientID string, scope *string) error

// DeviceAuthorizationConfig holds the options of the device-authorization plugin.
type DeviceAuthorizationConfig struct {
	// ExpiresIn is how long a device code / user code pair is valid (default 30 minutes).
	ExpiresIn time.Duration
	// Interval is the minimum time between two polls of POST /device/token (default 5 seconds); polling
	// faster gets `slow_down`.
	Interval time.Duration
	// DeviceCodeLength is the length of generated device codes (default 40, [a-zA-Z0-9]).
	DeviceCodeLength int
	// UserCodeLength is the length of generated user codes (default 8, UserCodeCharset).
	UserCodeLength int
	// GenerateDeviceCode replaces the default device code generator.
	GenerateDeviceCode GenerateCodeFunc
	// GenerateUserCode replaces the default user code generator. User codes are looked up after removing
	// dashes, so generated codes should not contain any.
	GenerateUserCode GenerateCodeFunc
	// ValidateClient checks client_id on /device/code and /device/token; nil accepts every client.
	ValidateClient ValidateClientFunc
	// OnDeviceAuthRequest is called for every accepted device authorization request.
	OnDeviceAuthRequest DeviceAuthRequestFunc
	// VerificationURI is where users enter their code: an absolute URL ("https://example.com/device") or a
	// path resolved against the auth base URL ("/device", the default). It is returned as verification_uri,
	// and with ?user_code=... as verification_uri_complete.
	VerificationURI string
	// ModelName renames the deviceCode table (better-auth's schema.deviceCode.modelName).
	ModelName string
	// FieldNames renames columns of the deviceCode table: logical field name → column
	// (better-auth's schema.deviceCode.fields).
	FieldNames map[string]string
}

// WithDefaults fills unset options with better-auth's defaults.
func (c DeviceAuthorizationConfig) WithDefaults() DeviceAuthorizationConfig {
	if c.ExpiresIn <= 0 {
		c.ExpiresIn = DefaultExpiresIn
	}
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.DeviceCodeLength <= 0 {
		c.DeviceCodeLength = DefaultDeviceCodeLength
	}
	if c.UserCodeLength <= 0 {
		c.UserCodeLength = DefaultUserCodeLength
	}
	return c
}
