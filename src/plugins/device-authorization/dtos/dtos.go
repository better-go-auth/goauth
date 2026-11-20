// Package dtos holds the request and response bodies of the device-authorization plugin (better-auth wire
// format, RFC 8628 snake_case names).
package dtos

import "time"

// Device code statuses stored in deviceCode.status.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
)

// GrantTypeDeviceCode is the grant_type of POST /device/token (RFC 8628 §3.4).
const GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceCodeRequest is the body of POST /device/code.
type DeviceCodeRequest struct {
	ClientID *string `json:"client_id,omitempty" doc:"The client ID of the application"`
	Scope    *string `json:"scope,omitempty" doc:"Space-separated list of scopes"`
}

// DeviceCodeResponse is the RFC 8628 §3.2 device authorization response.
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code" doc:"The device verification code"`
	UserCode                string `json:"user_code" doc:"The user code to display"`
	VerificationURI         string `json:"verification_uri" doc:"The URL for user verification"`
	VerificationURIComplete string `json:"verification_uri_complete" doc:"The verification URL with the user code as query parameter"`
	ExpiresIn               int64  `json:"expires_in" doc:"Lifetime in seconds of the device code"`
	Interval                int64  `json:"interval" doc:"Minimum polling interval in seconds"`
}

// DeviceTokenRequest is the body of POST /device/token.
type DeviceTokenRequest struct {
	GrantType  *string `json:"grant_type,omitempty" doc:"The grant type for device flow"`
	DeviceCode *string `json:"device_code,omitempty" doc:"The device verification code"`
	ClientID   *string `json:"client_id,omitempty" doc:"The client ID of the application"`
}

// DeviceTokenResponse is the successful token response: access_token is the new session's token, usable
// as a bearer token (bearer plugin) or as the session cookie value.
type DeviceTokenResponse struct {
	AccessToken string `json:"access_token" doc:"The session token"`
	TokenType   string `json:"token_type" doc:"Always Bearer"`
	ExpiresIn   int64  `json:"expires_in" doc:"Seconds until the session expires"`
	Scope       string `json:"scope" doc:"The scope requested with the device code"`
}

// DeviceVerifyResponse is the body of GET /device.
type DeviceVerifyResponse struct {
	UserCode string `json:"user_code" doc:"The user code as sent"`
	Status   string `json:"status" enum:"pending,approved,denied" doc:"Current status of the device authorization"`
}

// DeviceDecisionRequest is the body of POST /device/approve and POST /device/deny.
type DeviceDecisionRequest struct {
	UserCode *string `json:"userCode,omitempty" doc:"The user code to approve or deny"`
}

// DeviceSuccessResponse is {"success": true}.
type DeviceSuccessResponse struct {
	Success bool `json:"success"`
}

// OAuthErrorBody is the RFC 6749 style error body every device endpoint uses for its own errors.
type OAuthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// DeviceCode is a row of the deviceCode table.
type DeviceCode struct {
	ID         string
	DeviceCode string
	UserCode   string
	// UserID is set once a signed-in user opened GET /device with the user code (and on approve / deny).
	UserID    *string
	ExpiresAt time.Time
	// Status is StatusPending, StatusApproved or StatusDenied.
	Status       string
	LastPolledAt *time.Time
	// PollingInterval is the minimum polling interval in milliseconds.
	PollingInterval *float64
	ClientID        *string
	Scope           *string
}
