// Package dtos holds the request and response bodies of the username plugin (better-auth wire format).
package dtos

import "github.com/better-go-auth/goauth/src/models/dtos"

// SignInUsernameInput is the body of POST /sign-in/username.
type SignInUsernameInput struct {
	Username    string  `json:"username" doc:"The username of the user"`
	Password    string  `json:"password" doc:"The password of the user"`
	RememberMe  *bool   `json:"rememberMe,omitempty" doc:"Remember the user session"`
	CallbackURL *string `json:"callbackURL,omitempty" doc:"URL to redirect to after sign in"`
}

// SignInUsernameResponse is better-auth's {redirect, token, url, user}.
type SignInUsernameResponse struct {
	Redirect bool              `json:"redirect"`
	Token    string            `json:"token"`
	URL      *string           `json:"url,omitempty"`
	User     dtos.UserResponse `json:"user"`
}

// IsUsernameAvailableInput is the body of POST /is-username-available.
type IsUsernameAvailableInput struct {
	Username string `json:"username" doc:"The username to check"`
}

// IsUsernameAvailableResponse is {"available": bool}.
type IsUsernameAvailableResponse struct {
	Available bool `json:"available"`
}
