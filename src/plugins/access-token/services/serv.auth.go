// Package services implements the access-token (legacy JWT) authentication services,
// ported from src/app/core/auth, src/app/core/session, src/app/core/profile, and src/app/core/verification.
package services

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"

	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	errors "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
	model_dtos "github.com/better-go-auth/goauth/src/models/dtos"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	accTokInterfaces "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
)

// validEmail accepts only a bare address ("a@b.co"), rejecting display-name forms like "Bob <a@b.co>"
// (same rule as core sign-up).
func validEmail(email string) bool {
	a, err := mail.ParseAddress(email)
	return err == nil && a.Address == email
}

// validateRegisterInput checks a /signup body like core sign-up does: a bare email address and a password
// within EmailAndPassword.MinPasswordLength..MaxPasswordLength (default 8..128).
func (aus *AuthService) validateRegisterInput(input accesstokendtos.RegisterClientInput) error {
	// Step 1: the email must be a bare address
	if !validEmail(input.Email) {
		return autherr.ErrInvalidEmail
	}
	// Step 2: the password must be set and within the configured bounds
	if input.Password == "" {
		return autherr.ErrInvalidPassword
	}
	minLen, maxLen := aus.MinPasswordLength, aus.MaxPasswordLength
	if minLen <= 0 {
		minLen = 8
	}
	if maxLen <= 0 {
		maxLen = 128
	}
	if len(input.Password) < minLen {
		return autherr.ErrPasswordTooShort
	}
	if len(input.Password) > maxLen {
		return autherr.ErrPasswordTooLong
	}
	return nil
}

// RegisterWithEmail (acc-01) , [AccountStatus], set(pwd,)
func (aus *AuthService) RegisterWithEmail(ctx context.Context, input accesstokendtos.RegisterClientInput) (*svcint.SignUpResult, error) {
	// Step 1: validate the input (HTTP callers are also checked by Huma; Go callers only here)
	if err := aus.validateRegisterInput(input); err != nil {
		return nil, err
	}
	// Step 2: store emails lower-cased, as core sign-up does (sign-in looks them up lower-cased)
	input.Email = strings.ToLower(input.Email)
	// Step 3: an absent avatar is stored as NULL, not ""
	var image *string
	if input.Avatar != "" {
		avatar := input.Avatar
		image = &avatar
	}

	// Step 4: create the user and its credential account in one transaction
	var res *svcint.SignUpResult
	var created *models.User
	err := aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		existing, err := acceptNotFound(aus.UserRepo.FindUserByEmail(txCtx, input.Email))
		if err != nil {
			return err
		}
		if existing != nil {
			// hash anyway so both branches take the same time
			if _, err := aus.Passwords.HashContext(txCtx, input.Password); err != nil {
				return err
			}
			// generate clone user
			now := time.Now().UTC()
			res = &svcint.SignUpResult{User: modeldtos.UserResponse{
				ID: models.NewID(), Name: input.FirstName, Email: input.Email, Image: image,
				CreatedAt: modeldtos.Time(now), UpdatedAt: modeldtos.Time(now),
			}}
			// todo: add on existing user signup function here
			return nil

		}

		// new user: hash with the configured hasher (scrypt in compat mode)
		hash, err := aus.Passwords.HashContext(txCtx, input.Password)
		if err != nil {
			return err
		}
		u := &models.User{Base: models.Base{ID: models.NewID()}}
		u.Name, u.Email, u.Image, u.Role = input.FirstName, input.Email, image, enums.User
		u.FirstName, u.LastName = input.FirstName, input.LastName
		// u.AccountStatus = enums.AccountPendingVerification
		// better-auth keeps passwords on a "credential" account whose accountId is the user id, not on the user row
		account := &models.Account{
			Base:       models.Base{ID: models.NewID()},
			ProviderID: models.ProvCredential,
			Password:   &hash,
		}
		if aus.Internal != nil {
			// the internal adapter runs the database hooks (BeforeUserCreate / AfterUserCreate included)
			if created, err = aus.Internal.CreateUser(txCtx, u); err != nil {
				if ae := autherr.AsAuthError(err); ae != nil && !aus.Internal.IsCancelled(err) {
					return ae
				}
				return autherr.ErrFailedToCreateUser
			}
			account.UserID, account.AccountID = created.ID, created.ID
			if _, err = aus.Internal.LinkAccount(txCtx, account); err != nil && !aus.Internal.IsCancelled(err) {
				return autherr.ErrFailedToCreateUser
			}
		} else {
			if created, err = aus.UserRepo.CreateUser(txCtx, u); err != nil {
				return autherr.ErrFailedToCreateUser
			}
			account.UserID, account.AccountID = created.ID, created.ID
			if _, err = aus.AccountRepo.CreateAccount(txCtx, account); err != nil {
				return autherr.ErrFailedToCreateUser
			}
		}

		_, err = aus.VSvc.SendVerification(txCtx, input.Email, models.PurposeEmailVerification, &accTokInterfaces.VerOpt{UserId: created.ID})
		if err != nil {
			// todo: maybe we skip this error
			return err
		}
		if aus.Hooks != nil && aus.Internal == nil {
			if err := aus.Hooks.TriggerAfterUserCreate(txCtx, created); err != nil {
				return fmt.Errorf("authsvc: after user create hook: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// duplicate email handled generically: return the fake user, no email, no session
	if res != nil {
		return res, nil
	}

	return &svcint.SignUpResult{User: modeldtos.UserFromModel(created)}, nil
}

// Login (acc-03) [companyId, Role, Password]
func (aus *AuthService) Login(ctx context.Context, input accesstokendtos.LoginData) (dtos.GResp[accesstokendtos.TokenResponse], error) {
	if aus.coreAuthSvc == nil {
		return dtos.InternalErrMS[accesstokendtos.TokenResponse]("core auth service not available"), fmt.Errorf("core auth service not available")
	}
	// 1. Delegate verification, password check, rehash, bans, and session creation to core auth
	signInResult, err := aus.coreAuthSvc.SignInEmail(ctx, model_dtos.SignInEmailInput{
		Email:    input.LoginInfo,
		Password: input.Password,
	}, authint.SessionMeta{})
	if err != nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), err
	}

	if signInResult == nil || signInResult.Session == nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), errors.EmailOrPasswordErr
	}

	// 2. Access Token Plugin Duty: Issue JWT Access Token + Refresh Token
	tokens, err := aus.SesSvc.Tokens(&signInResult.Session.Session, signInResult.User.Role)
	if err != nil {
		return dtos.InternalErrMS[accesstokendtos.TokenResponse](err.Error()), err
	}

	return dtos.SuccessCreated(accesstokendtos.TokenResponse{
		AuthTokens: tokens,
		UserData:   signInResult.User,
	}, 1), nil
}

// ResetToken (acc-04) exchanges a refresh token (the session token) for new tokens.
func (aus *AuthService) ResetToken(ctx context.Context, refreshToken string) (dtos.GResp[accesstokendtos.TokenResponse], error) {
	// 1. check that the refresh token is not an access token JWT (3 segments)
	if strings.Count(refreshToken, ".") == 2 {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.InvalidToken), errors.InvalidTokenError
	}

	// 2. the refresh token must name a live session
	session, err := aus.SesSvc.FindByRefreshToken(ctx, refreshToken)
	if err != nil || session == nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.InvalidToken), errors.InvalidTokenError
	}

	// 3. get the user
	usr, err := aus.UserRepo.FindUserByID(ctx, session.UserID)
	if err != nil || usr == nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.DataNotFound), errors.UserNotFoundError
	}

	// 4. the user must still be allowed to sign in
	if usr.Banned && (usr.BanExpires == nil || usr.BanExpires.After(time.Now())) {
		_ = aus.SesSvc.DeleteSession(ctx, session.ID)
		return dtos.BadReqM[accesstokendtos.TokenResponse](errors.ErrUserBanned.Message), errors.ErrUserBanned
	}

	// 5. slide the session, rotate the refresh token (if configured) and sign a new access token
	tokens, err := aus.SesSvc.RefreshTokens(ctx, session, usr.Role.S())
	if err != nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.InvalidToken), errors.InvalidTokenError
	}

	return dtos.SuccessCreated(accesstokendtos.TokenResponse{
		AuthTokens: tokens,
		UserData:   model_dtos.UserFromModel(usr),
	}, 1), nil
}

// Logout revokes the session behind the refresh token.
func (aus *AuthService) Logout(ctx context.Context, refreshToken string) (dtos.GResp[bool], error) {
	// 1. check that the refresh token is not an access token JWT (3 segments)
	if strings.Count(refreshToken, ".") == 2 {
		return dtos.BadReqC[bool](errors.InvalidToken), errors.InvalidTokenError
	}

	// 2. lookup live session by refresh token
	session, err := aus.SesSvc.FindByRefreshToken(ctx, refreshToken)
	if err != nil || session == nil {
		return dtos.BadReqC[bool](errors.InvalidToken), errors.InvalidTokenError
	}

	// 3. delete session from storage and database
	if err := aus.SesSvc.DeleteSession(ctx, session.ID); err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}
	return dtos.SuccessCreated(true, 1), nil
}
