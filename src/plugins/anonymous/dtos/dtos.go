// Package dtos holds the response bodies of the anonymous plugin (better-auth wire format).
package dtos

import "github.com/better-go-auth/goauth/src/models/dtos"

// SignInAnonymousResponse is better-auth's {token, user}.
type SignInAnonymousResponse struct {
	Token string            `json:"token"`
	User  dtos.UserResponse `json:"user"`
}

// SuccessResponse is {"success": true}.
type SuccessResponse struct {
	Success bool `json:"success"`
}
