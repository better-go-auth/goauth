// Package services implements better-auth's username plugin: username + password sign-in, username
// availability checks and the username / displayUsername rules applied on sign-up and update-user.
package services

import (
	"context"
	"net/http"
	"unicode/utf16"

	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
)

// Body keys the plugin reads from /sign-up/email and /update-user.
const (
	BodyUsername        = "username"
	BodyDisplayUsername = "displayUsername"
)

// Go field names of the plugin's user columns (update maps).
const (
	FieldUsername        = "Username"
	FieldDisplayUsername = "DisplayUsername"
)

// Service holds the username plugin logic.
type Service struct {
	cfg      usernameconfig.UsernameConfig
	kit      *pluginkit.Kit
	verifier authsvc.VerificationSender
}

// NewService builds the service; cfg defaults are applied here. verifier (the core auth service) is used to
// re-send verification emails on sign-in and may be nil.
func NewService(cfg usernameconfig.UsernameConfig, kit *pluginkit.Kit, verifier authsvc.VerificationSender) *Service {
	return &Service{cfg: cfg.WithDefaults(), kit: kit, verifier: verifier}
}

// Config returns the effective configuration (defaults applied).
func (s *Service) Config() usernameconfig.UsernameConfig { return s.cfg }

// Kit returns the shared plugin runtime.
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// ─── Helpers ─────────────────────────────────────────────────────────────────

// jsLength is JavaScript's String.prototype.length (UTF-16 code units), which better-auth's limits use.
func jsLength(v string) int { return len(utf16.Encode([]rune(v))) }

// checkUsername applies the length limits and the validator, answering with status (400 or 422).
func (s *Service) checkUsername(username string, status int) error {
	if jsLength(username) < s.cfg.MinUsernameLength {
		return ErrUsernameTooShort.WithStatus(status)
	}
	if jsLength(username) > s.cfg.MaxUsernameLength {
		return ErrUsernameTooLong.WithStatus(status)
	}
	if !s.cfg.UsernameValidator(username) {
		return ErrInvalidUsername.WithStatus(status)
	}
	return nil
}

// checkDisplayUsername runs DisplayUsernameValidator (when configured) in the configured validation order.
func (s *Service) checkDisplayUsername(displayUsername string) error {
	if s.cfg.DisplayUsernameValidator == nil {
		return nil
	}
	value := displayUsername
	if s.cfg.ValidationOrder.DisplayUsername == usernameconfig.PostNormalization {
		value = s.cfg.NormalizeDisplay(displayUsername)
	}
	if !s.cfg.DisplayUsernameValidator(value) {
		return ErrInvalidDisplayUsername
	}
	return nil
}

// FindByUsername returns the live user with the exact (already normalized) username, or nil.
func (s *Service) FindByUsername(ctx context.Context, normalized string) (*models.User, error) {
	if normalized == "" {
		return nil, nil
	}
	return pluginkit.AcceptNotFound(s.kit.Repos.FindUserByUsername(ctx, normalized))
}

// validateUsername is better-auth's validateUsername used by the user create hook outside sign-up.
func (s *Service) validateUsername(ctx context.Context, username string, displayUsername *string, currentUserID string) error {
	// Step 1: length and format, on the raw or normalized value
	value := username
	if s.cfg.ValidationOrder.Username == usernameconfig.PostNormalization {
		value = s.cfg.Normalize(username)
	}
	if err := s.checkUsername(value, http.StatusBadRequest); err != nil {
		return err
	}
	// Step 2: uniqueness (the current user may keep their own username)
	existing, err := s.FindByUsername(ctx, s.cfg.Normalize(username))
	if err != nil {
		return err
	}
	if existing != nil && (currentUserID == "" || existing.ID != currentUserID) {
		return ErrUsernameTaken
	}
	// Step 3: display username format
	if displayUsername != nil && *displayUsername != "" {
		return s.checkDisplayUsername(*displayUsername)
	}
	return nil
}

func ptr(v string) *string { return &v }

// ─── Hooks ───────────────────────────────────────────────────────────────────

// OnUserInput is better-auth's before hook on /sign-up/email and /update-user plus the username /
// displayUsername additional fields: it validates the body values, rejects taken usernames and writes the
// normalized values onto the new user (sign-up) or the update (update-user).
func (s *Service) OnUserInput(ctx context.Context, ev *plugins.UserInputEvent) error {
	if ev == nil || (ev.Path != plugins.UserInputSignUpEmail && ev.Path != plugins.UserInputUpdateUser) {
		return nil
	}
	// Step 1: read the plugin's fields (strings, or null on update-user to clear them)
	rawUsername, usernameSent := ev.Body[BodyUsername]
	rawDisplay, displaySent := ev.Body[BodyDisplayUsername]
	username, usernameIsString := rawUsername.(string)
	display, displayIsString := rawDisplay.(string)
	if (usernameSent && rawUsername != nil && !usernameIsString) || (displaySent && rawDisplay != nil && !displayIsString) {
		return ErrInvalidUsername
	}

	// Step 2: validate the username (length, format) and its availability
	if usernameIsString {
		value := username
		if s.cfg.ValidationOrder.Username == usernameconfig.PostNormalization {
			value = s.cfg.Normalize(username)
		}
		if err := s.checkUsername(value, http.StatusBadRequest); err != nil {
			return err
		}
		existing, err := s.FindByUsername(ctx, s.cfg.Normalize(username))
		if err != nil {
			return err
		}
		// sign-up: any owner is a conflict; update-user: only another user's
		if existing != nil && (ev.Path == plugins.UserInputSignUpEmail || existing.ID != ev.UserID) {
			return ErrUsernameTaken
		}
	}
	// Step 3: validate the display username
	if displayIsString {
		if err := s.checkDisplayUsername(display); err != nil {
			return err
		}
	}

	// Step 4: sign-up fills each field from the other and sets them on the new user (normalized like the
	// schema's input transform; BeforeUserCreate normalizes once more like better-auth's database hook)
	if ev.Path == plugins.UserInputSignUpEmail {
		if ev.User == nil {
			return nil
		}
		if username != "" && display == "" {
			display = username
		}
		if display != "" && username == "" {
			username = display
		}
		if username != "" {
			ev.User.Username = ptr(s.cfg.Normalize(username))
		}
		if display != "" {
			ev.User.DisplayUsername = ptr(s.cfg.NormalizeDisplay(display))
		}
		return nil
	}

	// Step 5: update-user writes the normalized values (input transform + database update hook, both
	// normalizing like better-auth); null clears the field
	if ev.Update == nil {
		return nil
	}
	if usernameSent {
		if usernameIsString {
			ev.Update[FieldUsername] = ptr(s.cfg.Normalize(s.cfg.Normalize(username)))
		} else {
			ev.Update[FieldUsername] = nil
		}
	}
	if displaySent {
		switch {
		case !displayIsString:
			ev.Update[FieldDisplayUsername] = nil
		case display == "":
			ev.Update[FieldDisplayUsername] = ptr("")
		default:
			ev.Update[FieldDisplayUsername] = ptr(s.cfg.NormalizeDisplay(s.cfg.NormalizeDisplay(display)))
		}
	}
	return nil
}

// skipCreateValidation reports whether the request is /sign-up/email or /update-user, whose usernames were
// already validated by OnUserInput (better-auth's pathsWithHttpHookValidation).
func (s *Service) skipCreateValidation(ctx context.Context) bool {
	req := s.kit.Request(ctx)
	if req == nil || req.URL == nil {
		return false
	}
	return req.URL.Path == s.kit.Path(plugins.UserInputSignUpEmail) || req.URL.Path == s.kit.Path(plugins.UserInputUpdateUser)
}

// BeforeUserCreate is better-auth's databaseHooks.user.create.before: users created with a username by any
// endpoint (admin, plugins, ...) get it validated and normalized, and displayUsername defaults to it.
func (s *Service) BeforeUserCreate(ctx context.Context, user *models.User) error {
	if user == nil {
		return nil
	}
	// Step 1: goauth stores "no username" as NULL so the unique index never sees ""
	if user.Username != nil && *user.Username == "" {
		user.Username = nil
	}
	// Step 2: users without a username only get their display username normalized
	if user.Username == nil {
		if user.DisplayUsername != nil && *user.DisplayUsername != "" {
			user.DisplayUsername = ptr(s.cfg.NormalizeDisplay(*user.DisplayUsername))
		}
		return nil
	}
	// Step 3: validate unless the sign-up hook already did
	username := *user.Username
	if !s.skipCreateValidation(ctx) {
		if err := s.validateUsername(ctx, username, user.DisplayUsername, ""); err != nil {
			return err
		}
	}
	// Step 4: normalize, defaulting displayUsername to the username as given
	user.Username = ptr(s.cfg.Normalize(username))
	if user.DisplayUsername != nil && *user.DisplayUsername != "" {
		user.DisplayUsername = ptr(s.cfg.NormalizeDisplay(*user.DisplayUsername))
	} else {
		user.DisplayUsername = ptr(username)
	}
	return nil
}

// ─── Sign in with username + password ────────────────────────────────────────

// SignInInput is the body of POST /sign-in/username.
type SignInInput struct {
	Username    string
	Password    string
	RememberMe  *bool
	CallbackURL *string
}

// SignInResult is a successful username sign-in.
type SignInResult struct {
	Session      *dtos.SessionWithUser
	DontRemember bool
	// Redirect is true when a callbackURL was sent (the client follows URL).
	Redirect bool
	URL      *string
}

// SignIn mirrors POST /sign-in/username.
func (s *Service) SignIn(ctx context.Context, in SignInInput) (*SignInResult, error) {
	// Step 1: both fields are required
	if in.Username == "" || in.Password == "" {
		return nil, ErrInvalidUsernameOrPassword
	}
	// Step 2: format checks answer 422 (better-auth validates the normalized value with "pre-normalization")
	username := in.Username
	if s.cfg.ValidationOrder.Username == usernameconfig.PreNormalization {
		username = s.cfg.Normalize(username)
	}
	if err := s.checkUsername(username, http.StatusUnprocessableEntity); err != nil {
		return nil, err
	}
	// Step 3: find the user; unknown usernames still spend the hashing time
	user, err := s.FindByUsername(ctx, s.cfg.Normalize(username))
	if err != nil {
		return nil, err
	}
	if user == nil {
		_, _ = s.kit.Passwords.Hash(in.Password)
		return nil, ErrInvalidUsernameOrPassword
	}
	// Step 4: the password lives on the credential account
	acc, err := pluginkit.AcceptNotFound(s.kit.Repos.FindAccountByUserAndProvider(ctx, user.ID, models.ProvCredential))
	if err != nil {
		return nil, err
	}
	if acc == nil || acc.Password == nil || *acc.Password == "" {
		return nil, ErrInvalidUsernameOrPassword
	}
	if ok, _, err := s.kit.Passwords.Verify(*acc.Password, in.Password); err != nil || !ok {
		return nil, ErrInvalidUsernameOrPassword
	}
	// Step 5: RequireEmailVerification blocks unverified users (re-sending the email with SendOnSignIn)
	if s.kit.Conf.EmailAndPassword.RequireEmailVerification && !user.EmailVerified {
		if s.verifier == nil || !s.verifier.HasVerificationSender() {
			return nil, ErrEmailNotVerified
		}
		if s.kit.Conf.EmailVerification.SendOnSignIn {
			callbackURL := "/"
			if in.CallbackURL != nil && *in.CallbackURL != "" {
				callbackURL = *in.CallbackURL
			}
			if err := s.verifier.SendVerificationEmailTo(ctx, user, callbackURL); err != nil {
				return nil, err
			}
		}
		return nil, ErrEmailNotVerified
	}
	// Step 6: create the session (rememberMe=false → 1-day session without Max-Age)
	dontRemember := in.RememberMe != nil && !*in.RememberMe
	sw, err := s.kit.CreateSession(ctx, user, dontRemember)
	if err != nil {
		return nil, err
	}
	redirect := in.CallbackURL != nil && *in.CallbackURL != ""
	return &SignInResult{Session: sw, DontRemember: dontRemember, Redirect: redirect, URL: in.CallbackURL}, nil
}

// ─── Username availability ───────────────────────────────────────────────────

// IsUsernameAvailable mirrors POST /is-username-available.
func (s *Service) IsUsernameAvailable(ctx context.Context, username string) (bool, error) {
	// Step 1: format checks answer 422
	if username == "" {
		return false, ErrInvalidUsername.WithStatus(http.StatusUnprocessableEntity)
	}
	if err := s.checkUsername(username, http.StatusUnprocessableEntity); err != nil {
		return false, err
	}
	// Step 2: look up the normalized username
	existing, err := s.FindByUsername(ctx, s.cfg.Normalize(username))
	if err != nil {
		return false, err
	}
	return existing == nil, nil
}
