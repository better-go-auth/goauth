// Package dtos holds the response bodies of the anonymous plugin (better-auth wire format).
package dtos

import "github.com/better-go-auth/goauth/src/models/dtos"

// SignInAnonymousResponse is better-auth's {token, user}.
type SignInAnonymousResponse struct {
	Token string            `json:"token"`
	User  dtos.UserResponse `json:"user"`
}

// AnonymousSuccessResponse is {"success": true}. The name is unique among goauth's
// plugins because Huma names OpenAPI schemas after the Go type.
type AnonymousSuccessResponse struct {
	Success bool `json:"success"`
}

// SuccessResponse is AnonymousSuccessResponse (the name earlier goauth versions used).
type SuccessResponse = AnonymousSuccessResponse
