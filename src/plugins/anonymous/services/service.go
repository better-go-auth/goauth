// Package services implements better-auth's anonymous plugin: anonymous sign-in, deleting anonymous users
// and linking an anonymous user to the account it later signs in to (or signs up for).
package services

import (
	"context"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"

	"github.com/better-go-auth/goauth/src/app/services/userdelete"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins"
	anonconfig "github.com/better-go-auth/goauth/src/plugins/anonymous/config"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/idgen"
)

// SignInPath is the anonymous sign-in endpoint path.
const SignInPath = "/sign-in/anonymous"

// linkPathPrefixes are the paths better-auth's after hook watches for an anonymous user signing in to an
// account (sign-in / sign-up endpoints, OAuth callbacks, magic link, email OTP, passkey, phone number, ...).
var linkPathPrefixes = []string{
	"/sign-in", "/sign-up", "/callback", "/oauth2/callback", "/magic-link/verify", "/email-otp/verify-email",
	"/one-tap/callback", "/passkey/verify-authentication", "/phone-number/verify", "/verify-email",
}

// Service holds the anonymous plugin logic.
type Service struct {
	cfg anonconfig.AnonymousConfig
	kit *pluginkit.Kit
}

// NewService builds the service.
func NewService(cfg anonconfig.AnonymousConfig, kit *pluginkit.Kit) *Service {
	return &Service{cfg: cfg, kit: kit}
}

// Config returns the configuration.
func (s *Service) Config() anonconfig.AnonymousConfig { return s.cfg }

// Kit returns the shared plugin runtime.
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// ─── Sign in anonymously ─────────────────────────────────────────────────────

// email returns the new anonymous user's email (better-auth's getAnonUserEmail).
func (s *Service) email(ctx context.Context) (string, error) {
	// Step 1: the app's generator, which must return a bare address
	if s.cfg.GenerateRandomEmail != nil {
		if custom := s.cfg.GenerateRandomEmail(ctx); custom != "" {
			if a, err := mail.ParseAddress(custom); err != nil || a.Address != custom {
				return "", ErrInvalidEmailFormat
			}
			return custom, nil
		}
	}
	// Step 2: "temp-<id>@<domain>" or "temp@<id>.com"
	id := idgen.GenerateID()
	if s.cfg.EmailDomainName != "" {
		return "temp-" + id + "@" + s.cfg.EmailDomainName, nil
	}
	return "temp@" + id + ".com", nil
}

// SignIn mirrors POST /sign-in/anonymous: it creates an anonymous user and signs it in.
func (s *Service) SignIn(ctx context.Context) (*dtos.SessionWithUser, error) {
	// Step 1: an anonymous user may not create another anonymous user
	if current := s.kit.CurrentOrResolve(ctx); current != nil && current.User.IsAnonymous {
		return nil, ErrCannotSignInAgainAnonymously
	}
	// Step 2: email and name of the new user
	email, err := s.email(ctx)
	if err != nil {
		return nil, err
	}
	name := ""
	if s.cfg.GenerateName != nil {
		name = s.cfg.GenerateName(ctx, s.kit.Request(ctx))
	}
	if name == "" {
		name = anonconfig.DefaultName
	}
	// Step 3: create the user (user create hooks run like on any sign-up)
	user := &models.User{}
	user.Name, user.Email, user.EmailVerified, user.IsAnonymous, user.Role = name, strings.ToLower(email), false, true, enums.User
	created, err := s.kit.CreateUser(ctx, user)
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil && ae.Code != autherr.ErrFailedToCreateUser.Code {
			return nil, ae
		}
		return nil, ErrFailedToCreateUser
	}
	// Step 4: sign it in
	sw, err := s.kit.CreateSession(ctx, created, false)
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil && ae.Code != autherr.ErrFailedToCreateSession.Code {
			return nil, ae
		}
		return nil, ErrCouldNotCreateSession
	}
	return sw, nil
}

// ─── Delete anonymous user ───────────────────────────────────────────────────

// deleteUser removes an anonymous user with the shared deletion sequence (sessions, plugin rows through the
// UserDeleted hooks, accounts and the user row; a tombstone when config User.GoAuth.SoftDelete is on).
func (s *Service) deleteUser(ctx context.Context, userID string) error {
	return userdelete.Run(ctx, userdelete.Deps{
		Soft: s.kit.Conf.User.GoAuth.SoftDelete,
		// Step 1: sign the user out everywhere (DB and secondary storage)
		RevokeSessions: func(ctx context.Context, userID string) error {
			if err := s.kit.Sessions.DeleteUserSessions(ctx, userID); err != nil {
				return ErrFailedToDeleteAnonymousUserSessions
			}
			return nil
		},
		// Step 2: accounts and user together
		RemoveRows: func(ctx context.Context, userID string, soft bool) error {
			err := s.kit.InTx(ctx, func(ctx context.Context) error {
				if err := s.kit.Repos.DeleteAccounts(ctx, userID); err != nil {
					return err
				}
				if soft {
					return s.kit.Repos.SoftDeleteUser(ctx, userID)
				}
				return s.kit.Repos.DeleteUser(ctx, userID)
			})
			if err != nil {
				return ErrFailedToDeleteAnonymousUser
			}
			return nil
		},
		Hooks: s.kit.Hooks,
	}, userID)
}

// DeleteAnonymousUser mirrors POST /delete-anonymous-user (behind the fresh-session middleware).
func (s *Service) DeleteAnonymousUser(ctx context.Context) error {
	current := s.kit.Current(ctx)
	if current == nil {
		return autherr.ErrUnauthorized
	}
	// Step 1: the app may forbid deleting anonymous users
	if s.cfg.DisableDeleteAnonymousUser {
		return ErrDeleteAnonymousUserDisabled
	}
	// Step 2: only anonymous users can delete themselves here
	if !current.User.IsAnonymous {
		return ErrUserIsNotAnonymous
	}
	// Step 3: delete sessions and user
	return s.deleteUser(ctx, current.User.ID)
}

// ─── Account linking ─────────────────────────────────────────────────────────

// matchesLinkPath is better-auth's after-hook matcher.
func matchesLinkPath(path string) bool {
	for _, prefix := range linkPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// OnNewSession is better-auth's anonymous after hook: when a request carrying an anonymous session creates a
// session for another (non-anonymous) user, OnLinkAccount runs and the anonymous user is deleted.
func (s *Service) OnNewSession(ctx context.Context, ev plugins.NewSessionEvent) error {
	// Step 1: only sign-in / sign-up style endpoints
	if !matchesLinkPath(ev.Path) || ev.Session == nil {
		return nil
	}
	// Step 2: the request must carry an anonymous session
	var cookieHeader string
	if ev.Request != nil {
		cookieHeader = ev.Request.Header.Get("Cookie")
	}
	old, err := s.kit.Resolver.Resolve(ctx, cookieHeader)
	if err != nil || old == nil || !old.User.IsAnonymous {
		return nil
	}
	if old.Session.Token == ev.Session.Session.Token {
		return nil
	}
	// Step 3: let the app move the anonymous user's data
	if s.cfg.OnLinkAccount != nil {
		err := s.cfg.OnLinkAccount(ctx, anonconfig.LinkAccountData{AnonymousUser: old, NewUser: ev.Session, Request: ev.Request})
		if err != nil {
			if ae := autherr.AsAuthError(err); ae != nil {
				return ae
			}
			return autherr.ErrInternal.WithStatus(http.StatusInternalServerError)
		}
	}
	// Step 4: keep the anonymous user when deletion is disabled, the user is the same or still anonymous
	if s.cfg.DisableDeleteAnonymousUser || ev.Session.User.ID == old.User.ID || ev.Session.User.IsAnonymous {
		return nil
	}
	// Step 5: delete it (failures are logged, the sign-in still succeeds)
	if err := s.deleteUser(ctx, old.User.ID); err != nil {
		slog.Error("anonymous: failed to clean up anonymous user during post-link cleanup", "anonymousUserId", old.User.ID, "err", err)
	}
	return nil
}
