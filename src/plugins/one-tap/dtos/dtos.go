// Package dtos holds the request and response bodies of the one-tap endpoint.
package dtos

import modeldtos "github.com/better-go-auth/goauth/src/models/dtos"

// CallbackInput is the body of POST /one-tap/callback.
type CallbackInput struct {
	_ struct{} `additionalProperties:"true"`
	// IDToken is the Google ID token (the `credential` of the One Tap / Sign in with Google response).
	IDToken string `json:"idToken" doc:"Google ID token, which the client obtains from the One Tap API"`
}

// CallbackResponse is {token, user} after a successful sign-in, or {error} when the ID token carries no
// email (better-auth answers that case with 200 and only the error field).
type CallbackResponse struct {
	Token string                  `json:"token,omitempty"`
	User  *modeldtos.UserResponse `json:"user,omitempty"`
	Error string                  `json:"error,omitempty"`
}
