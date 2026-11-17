// Package dtos holds the request and response bodies of the multi-session endpoints.
package dtos

// SessionTokenInput is the body of /multi-session/set-active and /multi-session/revoke.
type SessionTokenInput struct {
	// SessionToken is the token of a session stored in one of the device's multi-session cookies.
	SessionToken string `json:"sessionToken" doc:"The session token"`
}

// StatusResponse is better-auth's {"status": true}.
type StatusResponse struct {
	Status bool `json:"status"`
}
