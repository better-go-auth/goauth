package authenticator

import (
	"context"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/idgen"
)

/*

Have an authenticator options

1. CtxOnlyLookup
2. Secondary storage lookup:
3. CheckDb
-------------------------

all authentication logic should happen on the middleware
- so all Db calls, secondary storage and etc should end on the middlware:

*/

// AuthenticateFunc authenticates an incoming request and returns the active SessionWithUser.
type AuthenticateFunc func(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionWithUser, error)

// SessionLookupRepo defines the data access methods required by Authenticator for fallback lookups.
type SessionLookupRepo interface {
	FindSession(ctx context.Context, token string) (*models.Session, error)
	FindUserByID(ctx context.Context, id string) (*models.User, error)
}

// TODO: this is an unneeded function, it will be removed, because all authentication should happen on the middleware
// may be we will provide this as a function, optional function for people to use outside the middleware
// so this will be a repeat of the authentication happening on the middleware, may be the middleware can re use this function or stg like that

// NewDefaultAuthenticator returns an AuthenticateFunc provided by the core to plugins.
// It handles:
//  1. Context claims (when Huma middleware has already authenticated the request; this is how legacy
//     access-token JWTs are accepted: the access-token plugin's middleware verifies them first)
//  2. Token extraction from Bearer Authorization header or session cookies
//  3. Database session and user lookup via SessionLookupRepo
//
// The core no longer verifies JWT access tokens itself; that logic lives in the access-token plugin.
func NewDefaultAuthenticator(lookup SessionLookupRepo) AuthenticateFunc {
	return func(ctx context.Context, auth humatypes.AuthHeaders) (*dtos.SessionWithUser, error) {
		// 1. Check if claims already exist in ctx (set by middleware)
		if sesResp, valid := SessionFromContext(ctx); valid {
			return sesResp, nil
		}

		// 2. Extract token from Authorization header or Cookie
		token := auth.Authorization
		if strings.HasPrefix(strings.ToLower(token), "bearer ") {
			token = strings.TrimSpace(token[7:])
		}
		// if the authorization token is empty, try to extract from cookie
		if token == "" && auth.Cookie != "" {
			parts := strings.Split(auth.Cookie, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "better-auth.session_token=") {
					token = strings.TrimPrefix(part, "better-auth.session_token=")
					break
				}
			}
		}

		if token == "" {
			return nil, autherr.ErrUnauthorized
		}

		// 3. Look up an opaque session token (shape-checked so stored refresh hashes can't be replayed)
		if lookup != nil && idgen.IsToken(token) {
			sess, err := lookup.FindSession(ctx, token)
			if err == nil && sess != nil && sess.UserID != "" {
				if sess.ExpiresAt.Before(time.Now().UTC()) {
					return nil, autherr.ErrUnauthorized
				}

				user, err := lookup.FindUserByID(ctx, sess.UserID)
				if err == nil && user != nil {
					return &dtos.SessionWithUser{
						User:    dtos.UserFromModel(user),
						Session: dtos.SessionFromModel(sess),
					}, nil
				}
			}
		}
		return nil, autherr.ErrUnauthorized
	}
}
