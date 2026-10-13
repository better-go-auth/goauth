// Package services implements the access-token (legacy JWT) authentication services,
// ported from src/app/core/auth, src/app/core/session, src/app/core/profile, and src/app/core/verification.
package services

import (
	"context"
	"fmt"
	"time"

	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	errors "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/models"
	model_dtos "github.com/better-go-auth/goauth/src/models/dtos"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	accTokInterfaces "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
)

// RegisterWithEmail (acc-01) , [AccountStatus], set(pwd,)
func (aus *AuthService) RegisterWithEmail(ctx context.Context, input models.RegisterClientInput) (*svcint.SignUpResult, error) {
	var res *svcint.SignUpResult
	var created *models.User
	err := aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		existing, err := acceptNotFound(aus.UserRepo.FindUserByEmail(ctx, input.Email))
		if err != nil {
			return err
		}
		if existing != nil {
			// hash anyway so both branches take the same time
			_, _ = aus.Passwords.Hash(input.Password)
			// generate clone user
			now := time.Now().UTC()
			res = &svcint.SignUpResult{User: modeldtos.UserResponse{
				ID: models.NewID(), Name: input.FirstName, Email: input.Email, Image: &input.Avatar,
				CreatedAt: modeldtos.Time(now), UpdatedAt: modeldtos.Time(now),
			}}
			// todo: add on existing user signup function here
			return nil

		}

		// new user: hash with the configured hasher (scrypt in compat mode)
		hash, err := aus.Passwords.Hash(input.Password)
		if err != nil {
			return err
		}
		u := &models.User{Base: models.Base{ID: models.NewID()}}
		u.Name, u.Email, u.Image, u.Role = input.FirstName, input.Email, &input.Avatar, enums.User
		if created, err = aus.UserRepo.CreateUser(ctx, u); err != nil {
			return autherr.ErrFailedToCreateUser
		}
		// better-auth keeps passwords on a "credential" account whose accountId is the user id, not on the user row
		_, err = aus.AccountRepo.CreateAccount(ctx, &models.Account{
			Base:       models.Base{ID: models.NewID()},
			UserID:     created.ID,
			ProviderID: models.ProvCredential,
			AccountID:  created.ID,
			Password:   &hash,
		})
		if err != nil {
			return autherr.ErrFailedToCreateUser
		}

		_, err = aus.VSvc.SendVerification(txCtx, input.Email, models.PurposeEmailVerification, &accTokInterfaces.VerOpt{UserId: created.ID})
		if err != nil {
			// todo: maybe we skip this error
			return err
		}
		if aus.Hooks != nil {
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

	return res, nil
}

// VerifyRegisteredUser (acc-01), [id]x
func (aus *AuthService) VerifyRegisteredUser(ctx context.Context, input accesstokendtos.VerificationInput) (res dtos.GResp[models.User], eror error) {
	var verifiedUser *models.User
	err := aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		usr, err := aus.UserRepo.FindUserByEmail(txCtx, input.Info)
		if err != nil || usr == nil || usr.AccountStatus != enums.AccountPendingVerification {
			return errors.InfoOrCodeErr
		}

		// Validate the code
		_, err = aus.VSvc.VerifyCode(txCtx, usr.GetEmail(), models.PurposeEmailVerification, input.Code)
		if err != nil {
			return errors.InfoOrCodeErr
		}

		// Update the user's status
		updatedUsr, err := aus.UserRepo.UpdateUser(txCtx, usr.ID, map[string]any{
			// "AccountStatus": enums.AccountActive,
			"Active":        true,
			"EmailVerified": true,
		})
		if err != nil {
			return err
		}
		verifiedUser = updatedUsr
		return nil
	})
	if err != nil {
		return dtos.InternalErrMS[models.User]("transaction Error"), err
	}
	// TODO: create a method that returns the verifid user
	return dtos.SuccessCreated(*verifiedUser, 1), nil
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

	// 1. check the user exists and is active
	// usr, err := aus.UserRepo.FindUserByEmail(ctx, input.LoginInfo)
	// // Active is goauth-only: nil means the user came from better-auth's sign-up and is allowed; false blocks login
	// if err != nil || usr == nil || (usr.Active != nil && !*usr.Active) {
	// 	_, _ = aus.Passwords.Hash(input.Password) // for security timing protection
	// 	return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), errors.EmailOrPasswordErr
	// }

	// 2. Get password from account record
	// account, err := aus.AccountRepo.FindAccountByUserAndProvider(ctx, usr.ID, models.ProvCredential)
	// if err != nil || account == nil || account.Password == nil {
	// 	_, _ = aus.Passwords.Hash(input.Password) // for security timing protection
	// 	return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), errors.ErrInvalidCredentials
	// }

	// // 3. compare the password hash
	// valid, upgraded, _ := aus.Passwords.Verify(*account.Password, input.Password)
	// if !valid {
	// 	return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), errors.EmailOrPasswordErr
	// }
	// if upgraded != "" {
	// 	if _, err := aus.AccountRepo.UpdateAccount(ctx, account.ID, map[string]interface{}{"Password": upgraded}); err != nil {
	// 		logger.ErrorCtx(ctx, "could not upgrade password hash", err, nil)
	// 	}
	// }

	// 4. Check ban (after credential check; expired bans are lifted silently)
	// if usr.Banned {
	// 	if usr.BanExpires == nil || usr.BanExpires.After(time.Now()) {
	// 		return dtos.BadReqM[accesstokendtos.TokenResponse](errors.ErrUserBanned.Message), errors.ErrUserBanned
	// 	}
	// 	// if the ban has expired lift the ban
	// 	_, _ = aus.UserRepo.UpdateUser(ctx, usr.ID, map[string]interface{}{
	// 		"Banned":     false,
	// 		"BanReason":  nil,
	// 		"BanExpires": nil,
	// 	})
	// }
	// setup active org id
	// now := time.Now()
	// updatedUsr, err := aus.UserRepo.UpdateUser(ctx, usr.ID, map[string]interface{}{
	// 	"LastLoginAt": now,
	// })
	// if err != nil {
	// 	logger.ErrorCtx(ctx, "could not update user last login at", err, nil)
	// 	return dtos.InternalErrMS[accesstokendtos.TokenResponse](err.Error()), err
	// }

	// TODO: know hos the create Session translates to the TOken
	// sessionID := models.NewSecureId()
	// tokens, err := aus.SesSvc.CreateSession(ctx, sessionID, usr.Role.S(), usr.ID, &models.SessionOpt{
	// 	ClearSession: aus.Config != nil && aus.Config.SingleSession,
	// 	DeviceToken:  input.DeviceToken,
	// })
	// if err != nil {
	// 	return dtos.InternalErrMS[accesstokendtos.TokenResponse](err.Error()), err
	// }

	// TODO: add audit log
	// tasks.EnqueueAuditActivityLog(ctx, aus.Provider.QueueClient, aus.Provider.GormConn, tasks.AuditActivityLogPayload{
	// 	CompanyID:   companyID,
	// 	UserID:      usr.Body.GetID(),
	// 	Action:      "LOGIN",
	// 	EntityType:  "user",
	// 	EntityID:    usr.Body.GetID(),
	// 	Summary:     "Logged in successfully",
	// 	LogAudit:    true,
	// 	LogActivity: true,
	// })

	return dtos.SuccessCreated(accesstokendtos.TokenResponse{
		AuthTokens: tokens,
		UserData:   signInResult.User,
	}, 1), nil
}

// ResetToken (acc-04) exchanges a refresh token (the session token) for new tokens.
func (aus *AuthService) ResetToken(ctx context.Context, refreshToken string) (dtos.GResp[accesstokendtos.TokenResponse], error) {
	// 1. the refresh token must name a live session
	session, err := aus.SesSvc.FindByRefreshToken(ctx, refreshToken)
	if err != nil || session == nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.InvalidToken), errors.InvalidTokenError
	}

	// 2. get the user
	usr, err := aus.UserRepo.FindUserByID(ctx, session.UserID)
	if err != nil || usr == nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.DataNotFound), errors.UserNotFoundError
	}

	// 3. the user must still be allowed to sign in
	if usr.Active != nil && !*usr.Active {
		_ = aus.SesSvc.DeleteSession(ctx, session.ID)
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.Unauthorized), errors.ErrUnauthorized
	}
	if usr.Banned && (usr.BanExpires == nil || usr.BanExpires.After(time.Now())) {
		_ = aus.SesSvc.DeleteSession(ctx, session.ID)
		return dtos.BadReqM[accesstokendtos.TokenResponse](errors.ErrUserBanned.Message), errors.ErrUserBanned
	}

	// 4. slide the session, rotate the refresh token (if configured) and sign a new access token
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
	session, err := aus.SesSvc.FindByRefreshToken(ctx, refreshToken)
	if err != nil || session == nil {
		return dtos.BadReqC[bool](errors.InvalidToken), errors.InvalidTokenError
	}
	if err := aus.SesSvc.DeleteSession(ctx, session.ID); err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}
	return dtos.SuccessCreated(true, 1), nil
}

// ForgotPwd [ID]
func (aus *AuthService) ForgotPwd(ctx context.Context, input accesstokendtos.VerifyReqInput) (dtos.GResp[bool], error) {
	usr, err := aus.UserRepo.FindUserByEmail(ctx, input.Email)
	if err != nil || usr == nil {
		return dtos.SuccessCreated(true, 0), nil
	}

	return aus.VSvc.SendVerification(ctx, input.Email, models.PurposePasswordReset, &accTokInterfaces.VerOpt{UserId: usr.ID})
}

// ResetPwd [ID]
func (aus *AuthService) ResetPwd(ctx context.Context, input accesstokendtos.PwdResetInput) (dtos.GResp[bool], error) {
	hash, err := aus.Passwords.Hash(input.NewPassword)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}

	usr, err := aus.UserRepo.FindUserByEmail(ctx, input.Info)
	if err != nil || usr == nil {
		return dtos.BadReqC[bool](errors.InfoOrCode), errors.InfoOrCodeErr
	}
	// Fetch sessions first so we don't lose their SessionId values upon deletion
	// sessions, fetchErr := generic.DbFetchManyWithOffset[models.Session](aus.Provider.GormConn, ctx, models.Session{UserID: usr.Body.ID}, dtos.PaginationInput{Limit: 10000}, nil)

	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		// 1. Validate the code
		_, err = aus.VSvc.VerifyCode(txCtx, input.Info, models.PurposePasswordReset, input.Code)
		if err != nil {
			return errors.InfoOrCodeErr
		}

		// 2. Update user's password
		account, err := aus.AccountRepo.FindAccountByUserAndProvider(txCtx, usr.ID, models.ProvCredential)
		if err != nil {
			return err
		}
		if account == nil {
			return errors.ErrInvalidCredentials
		}
		_, err = aus.AccountRepo.UpdateAccount(txCtx, account.ID, map[string]interface{}{"Password": hash})
		if err != nil {
			return fmt.Errorf("authsvc: update password: %w", err)
		}

		// 3. Clean up token
		if err := aus.VSvc.DeleteByIdentifier(txCtx, input.Info, models.PurposePasswordReset); err != nil {
			return fmt.Errorf("authsvc: deleting verification code: %w", err)
		}

		// 4. Delete all user sessions
		err = aus.SesSvc.DeleteAllUserSessions(txCtx, usr.ID)
		if err != nil {
			logger.LogError("Deleting user sessions errors", err.Error())
		}
		return nil
	})
	if err != nil {
		return dtos.InternalErrMS[bool]("transaction Error"), err
	}

	return dtos.SuccessCreated(true, 1), nil
}
