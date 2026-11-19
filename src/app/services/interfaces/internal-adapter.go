package interfaces

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/schema"
)

// IInternalAdapter is goauth's port of better-auth's internalAdapter: the one place core endpoints and
// plugins create, update and delete users, sessions, accounts and verifications. Every write runs the
// database hooks (AuthConfig.DatabaseHooks, plugin hooks, HookRegistry Before/AfterUserCreate), applies the
// schema registry (additionalFields defaults, field names) and keeps secondary storage / cached sessions in
// sync. SetupGoAuth builds it (GoAuth.Internal, InitContext.Internal).
//
// Errors: a database Before hook's error is returned unchanged (an *autherr.AuthError reaches the client as
// is); a cancelled create returns an error for which IsCancelled is true; other storage errors are returned
// as they come from the repositories. Cancelled updates and deletes are silent (better-auth's null).
type IInternalAdapter interface {
	// CreateUser inserts user (id, timestamps and lower-cased email filled in) with the user create hooks.
	CreateUser(ctx context.Context, user *models.User) (*models.User, error)
	// CreateOAuthUser inserts a user and its first account in one transaction (better-auth's createOAuthUser).
	CreateOAuthUser(ctx context.Context, user *models.User, account *models.Account) (*models.User, *models.Account, error)
	// UpdateUser applies data (better-auth field names; Go field names of models.User are accepted too) with
	// the user update hooks and rewrites the user copy of every session cached in secondary storage.
	UpdateUser(ctx context.Context, userID string, data map[string]any) (*models.User, error)
	// FindUserByID returns the user with its additional fields (better-auth's findUserById).
	FindUserByID(ctx context.Context, userID string) (*models.User, error)
	// DeleteUser deletes the user like better-auth (sessions, plugin rows through the UserDeleted hooks,
	// accounts, then the user row; User.GoAuth.SoftDelete keeps a tombstone), with the delete hooks.
	DeleteUser(ctx context.Context, userID string) error

	// CreateSession starts a session for user (BeforeSessionCreate hooks, session create hooks, schema
	// defaults of session additionalFields, secondary storage).
	CreateSession(ctx context.Context, user *models.User, meta SessionMeta, opts SessionCreateOptions) (*authdtos.SessionWithUser, error)
	// UpdateSession applies data (field names) to the session with the session update hooks and returns the
	// updated session, nil when it no longer exists.
	UpdateSession(ctx context.Context, current *authdtos.SessionWithUser, data map[string]any) (*authdtos.SessionWithUser, error)
	// DeleteSession revokes one session by token.
	DeleteSession(ctx context.Context, token string) error
	// DeleteUserSessions revokes every session of the user.
	DeleteUserSessions(ctx context.Context, userID string) error

	// LinkAccount inserts an account with the account create hooks (better-auth's linkAccount).
	LinkAccount(ctx context.Context, account *models.Account) (*models.Account, error)
	// UpdateAccount applies data to an account with the account update hooks.
	UpdateAccount(ctx context.Context, accountID string, data map[string]any) (*models.Account, error)
	// UpdatePassword sets the password hash of the user's credential account (better-auth's updatePassword).
	UpdatePassword(ctx context.Context, userID, hash string) error
	// DeleteAccount deletes one account by id.
	DeleteAccount(ctx context.Context, accountID string) error
	// DeleteAccounts deletes every account of the user.
	DeleteAccounts(ctx context.Context, userID string) error

	// CreateVerificationValue stores a verification (replacing rows with the same identifier).
	CreateVerificationValue(ctx context.Context, v *models.Verification) (*models.Verification, error)
	// FindVerificationValue returns the newest verification for identifier.
	FindVerificationValue(ctx context.Context, identifier string) (*models.Verification, error)
	// ConsumeVerificationValue atomically deletes and returns the newest live verification for identifier.
	ConsumeVerificationValue(ctx context.Context, identifier string) (*models.Verification, error)
	// DeleteVerificationByIdentifier deletes the verifications of identifier.
	DeleteVerificationByIdentifier(ctx context.Context, identifier string) error

	// ParseUserInput is better-auth's parseUserInput: a request body parsed against the user schema's input
	// fields (additionalFields, plugin fields, goauth's profile fields) for action create or update.
	ParseUserInput(data map[string]any, action schema.Action) (map[string]any, error)
	// ParseSessionInput is better-auth's parseSessionInput.
	ParseSessionInput(data map[string]any, action schema.Action) (map[string]any, error)
	// SetUserFields writes field-name values onto user: struct fields (converted to their Go types) and the
	// others into Extra. Keys that are not user fields are ignored.
	SetUserFields(user *models.User, data map[string]any) error
	// Schema returns the schema registry.
	Schema() *schema.Registry
	// Transaction runs fn in a transaction (when one is configured); database after hooks run once it
	// committed.
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
	// IsCancelled reports whether err comes from a database Before hook that cancelled the operation.
	IsCancelled(err error) bool
}
