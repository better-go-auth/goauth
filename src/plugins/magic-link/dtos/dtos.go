// Package dtos holds the request and response bodies of the magic-link endpoints.
package dtos

import "github.com/better-go-auth/goauth/src/models/dtos"

// SignInMagicLinkInput is the body of POST /sign-in/magic-link.
type SignInMagicLinkInput struct {
	Email              string         `json:"email" doc:"Email address to send the magic link"`
	Name               *string        `json:"name,omitempty" doc:"User display name. Only used if the user is registering for the first time"`
	CallbackURL        string         `json:"callbackURL,omitempty" doc:"URL to redirect after magic link verification"`
	NewUserCallbackURL string         `json:"newUserCallbackURL,omitempty" doc:"URL to redirect after new user signup"`
	ErrorCallbackURL   string         `json:"errorCallbackURL,omitempty" doc:"URL to redirect after error"`
	Metadata           map[string]any `json:"metadata,omitempty" doc:"Additional metadata to pass to sendMagicLink"`
}

// MagicLinkStatusResponse is better-auth's { status: true }. The name is unique among goauth's
// plugins because Huma names OpenAPI schemas after the Go type.
type MagicLinkStatusResponse struct {
	Status bool `json:"status"`
}

// StatusResponse is MagicLinkStatusResponse (the name earlier goauth versions used).
type StatusResponse = MagicLinkStatusResponse

// VerifyMagicLinkResponse is the JSON body of GET /magic-link/verify without callbackURL.
type VerifyMagicLinkResponse struct {
	Token   string            `json:"token"`
	User    dtos.UserResponse `json:"user"`
	Session dtos.SessionData  `json:"session"`
}

// TokenValue is the JSON stored in the verification row's value (better-auth's { email, name }).
type TokenValue struct {
	Email string  `json:"email"`
	Name  *string `json:"name,omitempty"`
}
