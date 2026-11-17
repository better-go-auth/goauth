// Package dtos holds the request and response bodies of the generic-oauth endpoints.
package dtos

// SignInOAuth2Input is the body of POST /sign-in/oauth2.
type SignInOAuth2Input struct {
	_                  struct{}       `additionalProperties:"true"`
	ProviderID         string         `json:"providerId" doc:"The provider ID for the OAuth provider"`
	CallbackURL        string         `json:"callbackURL,omitempty" doc:"The URL to redirect to after sign in"`
	ErrorCallbackURL   string         `json:"errorCallbackURL,omitempty" doc:"The URL to redirect to if an error occurs"`
	NewUserCallbackURL string         `json:"newUserCallbackURL,omitempty" doc:"The URL to redirect to after login if the user is new"`
	DisableRedirect    bool           `json:"disableRedirect,omitempty" doc:"Disable redirect"`
	Scopes             []string       `json:"scopes,omitempty" doc:"Scopes to be passed to the provider authorization request"`
	RequestSignUp      bool           `json:"requestSignUp,omitempty" doc:"Explicitly request sign-up (for providers with disableImplicitSignUp)"`
	AdditionalData     map[string]any `json:"additionalData,omitempty" doc:"Additional data stored in the OAuth state"`
}

// OAuth2LinkInput is the body of POST /oauth2/link.
type OAuth2LinkInput struct {
	_                struct{} `additionalProperties:"true"`
	ProviderID       string   `json:"providerId" doc:"The provider ID for the OAuth provider"`
	CallbackURL      string   `json:"callbackURL" doc:"The URL to redirect to once the account is linked"`
	Scopes           []string `json:"scopes,omitempty" doc:"Additional scopes to request when linking the account"`
	ErrorCallbackURL string   `json:"errorCallbackURL,omitempty" doc:"The URL to redirect to if there is an error during the link process"`
}

// RedirectResponse is {url, redirect}: the body of /sign-in/oauth2 and /oauth2/link.
type RedirectResponse struct {
	URL      string `json:"url" doc:"The authorization URL to redirect the user to"`
	Redirect bool   `json:"redirect" doc:"Whether the client should redirect to url"`
}
