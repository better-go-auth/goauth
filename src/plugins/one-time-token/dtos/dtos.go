// Package dtos holds the request and response bodies of the one-time-token endpoints.
package dtos

// TokenResponse is the body of GET /one-time-token/generate.
type TokenResponse struct {
	Token string `json:"token"`
}

// VerifyInput is the body of POST /one-time-token/verify.
type VerifyInput struct {
	// Token is the one-time token to verify.
	Token string `json:"token" doc:"The token to verify. Eg: \"some-token\""`
}
