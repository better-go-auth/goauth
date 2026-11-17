// Package config holds the options of the anonymous plugin (better-auth's AnonymousOptions).
package config

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/models/dtos"
)

// DefaultName is the name of anonymous users when GenerateName is not set.
const DefaultName = "Anonymous"

// LinkAccountData is passed to OnLinkAccount when an anonymous user signs in to (or signs up for) a real account.
type LinkAccountData struct {
	// AnonymousUser is the anonymous session the request carried.
	AnonymousUser *dtos.SessionWithUser
	// NewUser is the session the request created.
	NewUser *dtos.SessionWithUser
	// Request is the incoming HTTP request.
	Request *http.Request
}

// OnLinkAccountFunc moves the anonymous user's data to the new account. A returned error is sent as the
// response (the new session was already created, as in better-auth).
type OnLinkAccountFunc func(ctx context.Context, data LinkAccountData) error

// GenerateNameFunc returns the name of a new anonymous user (better-auth's generateName(ctx)).
type GenerateNameFunc func(ctx context.Context, request *http.Request) string

// GenerateRandomEmailFunc returns the email of a new anonymous user; it must be a valid address.
type GenerateRandomEmailFunc func(ctx context.Context) string

// AnonymousConfig mirrors better-auth's anonymous() options.
type AnonymousConfig struct {
	// EmailDomainName builds emails as "temp-<id>@<EmailDomainName>" (default "temp@<id>.com").
	EmailDomainName string
	// GenerateName names new anonymous users (default "Anonymous").
	GenerateName GenerateNameFunc
	// GenerateRandomEmail replaces the generated email (400 INVALID_EMAIL_FORMAT when it is not an email).
	GenerateRandomEmail GenerateRandomEmailFunc
	// OnLinkAccount runs when a request carrying an anonymous session creates a session for an account.
	OnLinkAccount OnLinkAccountFunc
	// DisableDeleteAnonymousUser keeps anonymous users after linking and disables /delete-anonymous-user.
	DisableDeleteAnonymousUser bool
}
