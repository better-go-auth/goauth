package auth

import (
	"context"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// GetSession mirrors better-auth's get-session: it loads the session and applies the sliding refresh.
// A nil result Session means there is no live session (the adapter clears the cookies).
func (s *Service) GetSession(ctx context.Context, token string, opt GetSessionOptions) (*GetSessionResult, error) {
	sw, err := s.sessions.Get(ctx, token)
	if err != nil {
		return nil, autherr.ErrFailedToGetSession
	}
	if sw == nil {
		return &GetSessionResult{}, nil
	}
	needsRefresh := !opt.DisableRefresh && s.sessions.ShouldRefresh(sw, opt.DontRemember)
	if opt.DeferRefresh || !needsRefresh {
		return &GetSessionResult{Session: sw, NeedsRefresh: needsRefresh}, nil
	}
	refreshed, err := s.sessions.Refresh(ctx, sw)
	if err != nil {
		return nil, autherr.ErrFailedToGetSession
	}
	if refreshed == nil {
		// the session vanished while refreshing; the adapter clears the cookies
		return nil, autherr.ErrFailedToGetSession.WithStatus(http.StatusUnauthorized)
	}
	return &GetSessionResult{Session: refreshed, Refreshed: true}, nil
}

// ListSessions mirrors better-auth's GET /list-sessions.
func (s *Service) ListSessions(ctx context.Context, current *dtos.SessionWithUser) ([]dtos.BetterAuthSession, error) {
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	return s.sessions.List(ctx, current.User.ID)
}

// RevokeSession mirrors better-auth's POST /revoke-session: tokens of other users are ignored silently.
func (s *Service) RevokeSession(ctx context.Context, current *dtos.SessionWithUser, token string) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	target, err := s.sessions.Get(ctx, token)
	if err != nil {
		return err
	}
	if target == nil || target.Session.UserID != current.User.ID {
		return nil
	}
	return s.sessions.Delete(ctx, token)
}

// RevokeSessions mirrors better-auth's POST /revoke-sessions (every session of the user, including the current one).
func (s *Service) RevokeSessions(ctx context.Context, current *dtos.SessionWithUser) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	return s.sessions.DeleteUserSessions(ctx, current.User.ID)
}

// RevokeOtherSessions mirrors better-auth's POST /revoke-other-sessions.
func (s *Service) RevokeOtherSessions(ctx context.Context, current *dtos.SessionWithUser) error {
	if current == nil {
		return autherr.ErrUnauthorized
	}
	list, err := s.sessions.List(ctx, current.User.ID)
	if err != nil {
		return err
	}
	for _, other := range list {
		if other.Token == current.Session.Token {
			continue
		}
		if err := s.sessions.Delete(ctx, other.Token); err != nil {
			return err
		}
	}
	return nil
}
