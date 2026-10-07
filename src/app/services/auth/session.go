package auth

import (
	"context"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// GetSession mirrors better-auth's get-session: it loads the session and applies the sliding refresh.
// A nil result Session means there is no live session (the adapter clears the cookies).
//
// Sliding refresh: once Session.UpdateAge (default 1 day) has passed since the expiry was last set, the expiry
// is pushed to now + Session.ExpiresIn (default 7 days), so active users stay signed in.
func (s *Service) GetSession(ctx context.Context, token string, opt GetSessionOptions) (*GetSessionResult, error) {
	// the manager reads secondary storage first, then the DB (per the session config), and drops expired sessions
	sw, err := s.sessions.Get(ctx, token)
	if err != nil {
		return nil, autherr.ErrFailedToGetSession
	}
	if sw == nil {
		return &GetSessionResult{}, nil
	}
	// ShouldRefresh applies config: Session.UpdateAge and Session.DisableSessionRefresh;
	// rememberMe=false sessions (dont_remember cookie) are never extended; the disableRefresh query skips it too
	needsRefresh := !opt.DisableRefresh && s.sessions.ShouldRefresh(sw, opt.DontRemember)
	// config: Session.DeferSessionRefresh → GET only reports needsRefresh, a later POST does the write
	if opt.DeferRefresh || !needsRefresh {
		return &GetSessionResult{Session: sw, NeedsRefresh: needsRefresh}, nil
	}
	// extend the expiry in the DB and/or secondary storage
	refreshed, err := s.sessions.Refresh(ctx, sw)
	if err != nil {
		return nil, autherr.ErrFailedToGetSession
	}
	if refreshed == nil {
		// the session vanished while refreshing; the adapter clears the cookies
		return nil, autherr.ErrFailedToGetSession.WithStatus(http.StatusUnauthorized)
	}
	// Refreshed tells the adapter to re-send the session cookie with the new Max-Age
	return &GetSessionResult{Session: refreshed, Refreshed: true}, nil
}

// ListSessions mirrors better-auth's GET /list-sessions: the signed-in user's live sessions (one per device).
// With secondary storage only, the manager reads them from the "active-sessions-<userId>" list.
func (s *Service) ListSessions(ctx context.Context, current *dtos.SessionWithUser) ([]dtos.BetterAuthSession, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	return s.sessions.List(ctx, current.User.ID)
}

// RevokeSession mirrors better-auth's POST /revoke-session: tokens of other users are ignored silently.
// (Returning success instead of an error doesn't tell the caller whether a foreign token exists.)
func (s *Service) RevokeSession(ctx context.Context, current *dtos.SessionWithUser, token string) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	target, err := s.sessions.Get(ctx, token)
	if err != nil {
		return err
	}
	// only the owner can revoke a session
	if target == nil || target.Session.UserID != current.User.ID {
		return nil
	}
	return s.sessions.Delete(ctx, token)
}

// UpdateSession mirrors better-auth's POST /update-session for the fields in GoAuth.Session.UpdatableFields
// (default: the device fields deviceToken, deviceId, deviceName, deviceType).
// Unknown keys are ignored like better-auth does; protected session fields get FIELD_NOT_ALLOWED;
// a body with nothing writable gets "No fields to update".
func (s *Service) UpdateSession(ctx context.Context, current *dtos.SessionWithUser, fields map[string]any) (*dtos.SessionWithUser, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	data := map[string]any{}
	for name, v := range fields {
		goName, ok := s.sessionFields[name]
		if !ok {
			if protectedSessionFields[name] {
				return nil, autherr.ErrFieldNotAllowed.WithMessage("Field " + name + " is not allowed to be set")
			}
			continue
		}
		switch v.(type) {
		case string, nil:
			data[goName] = v
		default:
			return nil, autherr.ErrValidationError.WithMessage(name + " must be a string or null")
		}
	}
	if len(data) == 0 {
		return nil, ErrNoFieldsToUpdate
	}
	sw, err := s.sessions.Update(ctx, current, data)
	if err != nil {
		return nil, err
	}
	if sw == nil {
		// revoked or expired meanwhile: fail closed instead of writing a cookie for a dead session
		return nil, autherr.ErrFailedToGetSession.WithStatus(http.StatusUnauthorized)
	}
	return sw, nil
}

// RevokeSessions mirrors better-auth's POST /revoke-sessions (every session of the user, including the current one).
func (s *Service) RevokeSessions(ctx context.Context, current *dtos.SessionWithUser) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	return s.sessions.DeleteUserSessions(ctx, current.User.ID)
}

// RevokeOtherSessions mirrors better-auth's POST /revoke-other-sessions: signs out every other device
// and keeps the one making the request.
func (s *Service) RevokeOtherSessions(ctx context.Context, current *dtos.SessionWithUser) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	list, err := s.sessions.List(ctx, current.User.ID)
	if err != nil {
		return err
	}
	for _, other := range list {
		// keep the caller's own session
		if other.Token == current.Session.Token {
			continue
		}
		if err := s.sessions.Delete(ctx, other.Token); err != nil {
			return err
		}
	}
	return nil
}
