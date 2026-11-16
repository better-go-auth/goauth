// Package dtos holds the request and response bodies of the social sign-in endpoints.
package dtos

import (
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
)

// IDTokenUserName is the name part of IDTokenUser.
type IDTokenUserName struct {
	_         struct{} `additionalProperties:"true"`
	FirstName string   `json:"firstName,omitempty"`
	LastName  string   `json:"lastName,omitempty"`
}

// IDTokenUser is the optional user object some providers (Apple) only send once.
type IDTokenUser struct {
	_     struct{}         `additionalProperties:"true"`
	Name  *IDTokenUserName `json:"name,omitempty"`
	Email string           `json:"email,omitempty"`
}

// IDTokenInput is the idToken body field of /sign-in/social and /link-social.
type IDTokenInput struct {
	_            struct{}     `additionalProperties:"true"`
	Token        string       `json:"token" doc:"ID token from the provider"`
	Nonce        string       `json:"nonce,omitempty" doc:"Nonce used to generate the token"`
	AccessToken  string       `json:"accessToken,omitempty" doc:"Access token from the provider"`
	RefreshToken string       `json:"refreshToken,omitempty" doc:"Refresh token from the provider"`
	ExpiresAt    *float64     `json:"expiresAt,omitempty" doc:"Expiry date of the token"`
	Scopes       []string     `json:"scopes,omitempty" doc:"Scopes granted (link-social)"`
	User         *IDTokenUser `json:"user,omitempty" doc:"The user object from the provider (Apple)"`
}

// SignInSocialInput is the body of POST /sign-in/social.
type SignInSocialInput struct {
	_                  struct{}       `additionalProperties:"true"`
	Provider           string         `json:"provider" doc:"Social provider id"`
	CallbackURL        string         `json:"callbackURL,omitempty" doc:"Callback URL to redirect to after the user has signed in"`
	NewUserCallbackURL string         `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string         `json:"errorCallbackURL,omitempty" doc:"Callback URL to redirect to if an error happens"`
	DisableRedirect    bool           `json:"disableRedirect,omitempty" doc:"Disable automatic redirection to the provider"`
	IDToken            *IDTokenInput  `json:"idToken,omitempty"`
	Scopes             []string       `json:"scopes,omitempty" doc:"Scopes to request in addition to the default ones"`
	RequestSignUp      bool           `json:"requestSignUp,omitempty" doc:"Explicitly request sign-up"`
	LoginHint          string         `json:"loginHint,omitempty" doc:"Login hint for the authorization request"`
	AdditionalData     map[string]any `json:"additionalData,omitempty" doc:"Additional data passed through the OAuth flow"`
}

// LinkSocialInput is the body of POST /link-social.
type LinkSocialInput struct {
	_                struct{}       `additionalProperties:"true"`
	Provider         string         `json:"provider"`
	CallbackURL      string         `json:"callbackURL,omitempty"`
	IDToken          *IDTokenInput  `json:"idToken,omitempty"`
	RequestSignUp    bool           `json:"requestSignUp,omitempty"`
	Scopes           []string       `json:"scopes,omitempty"`
	ErrorCallbackURL string         `json:"errorCallbackURL,omitempty"`
	DisableRedirect  bool           `json:"disableRedirect,omitempty"`
	AdditionalData   map[string]any `json:"additionalData,omitempty"`
}

// SignInSocialResponse is {url, redirect} (redirect branch) or {redirect:false, token, user} (idToken branch).
type SignInSocialResponse struct {
	Redirect bool                    `json:"redirect"`
	Token    string                  `json:"token,omitempty"`
	URL      string                  `json:"url,omitempty"`
	User     *modeldtos.UserResponse `json:"user,omitempty"`
}

// LinkSocialResponse is {url, redirect} or {url:"", status:true, redirect:false}.
type LinkSocialResponse struct {
	URL      string `json:"url"`
	Status   *bool  `json:"status,omitempty"`
	Redirect bool   `json:"redirect"`
}

// AccountTokenInput is the body of /get-access-token and /refresh-token.
type AccountTokenInput struct {
	_          struct{} `additionalProperties:"true"`
	ProviderID string   `json:"providerId" doc:"The provider ID for the OAuth provider"`
	AccountID  string   `json:"accountId,omitempty" doc:"The account ID associated with the refresh token"`
	UserID     string   `json:"userId,omitempty" doc:"The user ID associated with the account"`
}

// AccessTokenResponse is the body of /get-access-token.
type AccessTokenResponse struct {
	AccessToken          string          `json:"accessToken"`
	AccessTokenExpiresAt *modeldtos.Time `json:"accessTokenExpiresAt,omitempty"`
	Scopes               []string        `json:"scopes"`
	IDToken              *string         `json:"idToken,omitempty"`
}

// RefreshTokenResponse is the body of /refresh-token.
type RefreshTokenResponse struct {
	AccessToken           string          `json:"accessToken,omitempty"`
	RefreshToken          string          `json:"refreshToken,omitempty"`
	AccessTokenExpiresAt  *modeldtos.Time `json:"accessTokenExpiresAt,omitempty"`
	RefreshTokenExpiresAt *modeldtos.Time `json:"refreshTokenExpiresAt,omitempty"`
	Scope                 *string         `json:"scope"`
	IDToken               *string         `json:"idToken,omitempty"`
	ProviderID            string          `json:"providerId"`
	AccountID             string          `json:"accountId"`
}

// AccountInfoUser is the user part of /account-info.
type AccountInfoUser struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	Image         string `json:"image,omitempty"`
	EmailVerified bool   `json:"emailVerified"`
}

// AccountInfoResponse is the body of /account-info.
type AccountInfoResponse struct {
	User AccountInfoUser `json:"user"`
	Data map[string]any  `json:"data"`
}
