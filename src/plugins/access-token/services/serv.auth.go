// Package services implements the access-token (legacy JWT) authentication services,
// ported from src/app/core/auth, src/app/core/session, src/app/core/profile, and src/app/core/verification.
package services

import (
	"context"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	interfaces1 "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	errors "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// AuthService implements IAccessTokenAuthService for legacy JWT/token authentication.
type AuthService struct {
	Config   *config.SessionGoAuth
	Provider *providers.IProviderS
	// services
	VSvc   interfaces1.IVerificationService
	SesSvc *SessionService
	// repos
	UserRepo    repo_interfaces.IUserRepo
	AccountRepo repo_interfaces.IOAuthAccountRepo
	SessionRepo repo_interfaces.ISessionRepo
	// hooks & txn
	TxMgr interfaces.ITransactionManager
	Hooks plugins.HookRegistry
	// Passwords hashes/verifies passwords; nil means legacy bcrypt.
	Passwords *authcrypto.Passwords
}

var _ IAccessTokenAuthService = (*AuthService)(nil)

// NewAuthService creates a new AuthService for the access-token plugin.
func NewAuthService(
	conf *config.SessionGoAuth,
	vSvc interfaces1.IVerificationService,
	sSvc *SessionService,
	authRepos repo_interfaces.IAuthRepos,
	txMgr interfaces.ITransactionManager,
	passwords *authcrypto.Passwords,
	hooks ...plugins.HookRegistry,
) *AuthService {
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}
	return &AuthService{
		Config:      conf,
		VSvc:        vSvc,
		SesSvc:      sSvc,
		UserRepo:    authRepos,
		AccountRepo: authRepos,
		SessionRepo: authRepos,
		TxMgr:       txMgr,
		Passwords:   passwords,
		Hooks:       h,
	}
}

// RegisterWithEmail (acc-01) , [AccountStatus], set(pwd,)
func (aus *AuthService) RegisterWithEmail(ctx context.Context, input models.RegisterClientInput) (res dtos.GResp[models.User], eror error) {
	// Check if the email already exists
	usr, err := aus.UserRepo.FindUserByEmail(ctx, input.Email)
	if err == nil && usr != nil {
		// If the User is still pending verification, throw error
		// todo create a time out
		// if usr.AccountStatus != enums.AccountPendingVerification {
		// 	return dtos.BadReqC[models.User](errors.UserExists), errors.UserExistError
		// }
	}

	hash, err := aus.Passwords.Hash(input.Password)
	if err != nil {
		return dtos.InternalErrMS[models.User]("Hashing Error"), err
	}

	var createdUser *models.User
	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		existingUser, getErr := aus.UserRepo.FindUserByEmail(txCtx, input.Email)
		//user exists
		if getErr == nil && existingUser != nil {
			// Update pending verification user
			updated, err := aus.UserRepo.UpdateUser(txCtx, existingUser.ID, map[string]interface{}{
				// "password":       hash,
				"FirstName":     input.FirstName,
				"LastName":      input.LastName,
				// "AccountStatus": enums.AccountPendingVerification,
				// is this ptr or actual value
				"Role":   enums.User.S(),
				"Active": false,
			})
			if err != nil {
				return err
			}
			createdUser = updated
		} else {
			newUser := &models.User{
				UserDto: models.UserDto{
					FirstName: input.FirstName,
					LastName:  input.LastName,
					Email:     input.Email,
					// Password:      hash,
					Role:          enums.User,
					// AccountStatus: enums.AccountPendingVerification,
					Active:        new(bool), // false
				},
			}
			created, err := aus.UserRepo.CreateUser(txCtx, newUser)
			if err != nil {
				logger.LogTrace("error crating", err)
				return err
			}
			createdUser = created
		}

		now := time.Now()
		// 5. Create email/password account record
		pwdAccount := &models.Account{
			Base:       models.Base{ID: models.NewID(), CreatedAt: now, UpdatedAt: now},
			UserID:     createdUser.ID,
			ProviderID: models.ProvCredential,
			AccountID:  input.Email,
			Password:   &hash,
		}
		if _, err := aus.AccountRepo.CreateAccount(txCtx, pwdAccount); err != nil {
			// if account already exists for user and provider, update password
			if existingAcc, _ := aus.AccountRepo.FindAccountByUserAndProvider(txCtx, createdUser.ID, models.ProvCredential); existingAcc != nil {
				_, _ = aus.AccountRepo.UpdateAccount(txCtx, existingAcc.ID, map[string]interface{}{"Password": hash})
			} else {
				return fmt.Errorf("authsvc: create account: %w", err)
			}
		}

		_, err = aus.VSvc.SendVerification(txCtx, input.Email, models.PurposeEmailVerification, &interfaces1.VerOpt{UserId: createdUser.ID})
		if err != nil {
			// todo: maybe we skip this error
			return err
		}

		if aus.Hooks != nil {
			if err := aus.Hooks.TriggerAfterUserCreate(txCtx, createdUser); err != nil {
				return fmt.Errorf("authsvc: after user create hook: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return dtos.InternalErrMS[models.User]("transaction Error"), err
	}

	return dtos.SuccessCreated(*createdUser, 1), nil
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
		updatedUsr, err := aus.UserRepo.UpdateUser(txCtx, usr.ID, map[string]interface{}{
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
	// 1. check the user exists and is active
	usr, err := aus.UserRepo.FindUserByEmail(ctx, input.LoginInfo)
	// Active is goauth-only: nil means the user came from better-auth's sign-up and is allowed; false blocks login
	if err != nil || usr == nil || (usr.Active != nil && !*usr.Active) {
		_, _ = aus.Passwords.Hash(input.Password) // for security timing protection
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), errors.EmailOrPasswordErr
	}

	// 2. Get password from account record
	account, err := aus.AccountRepo.FindAccountByUserAndProvider(ctx, usr.ID, models.ProvCredential)
	if err != nil || account == nil || account.Password == nil {
		_, _ = aus.Passwords.Hash(input.Password) // for security timing protection
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), errors.ErrInvalidCredentials
	}

	// 3. compare the password hash
	valid, upgraded, _ := aus.Passwords.Verify(*account.Password, input.Password)
	if !valid {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), errors.EmailOrPasswordErr
	}
	if upgraded != "" {
		if _, err := aus.AccountRepo.UpdateAccount(ctx, account.ID, map[string]interface{}{"Password": upgraded}); err != nil {
			logger.ErrorCtx(ctx, "could not upgrade password hash", err, nil)
		}
	}

	// 4. Check ban (after credential check; expired bans are lifted silently)
	if usr.Banned {
		if usr.BanExpires == nil || usr.BanExpires.After(time.Now()) {
			return dtos.BadReqM[accesstokendtos.TokenResponse](errors.ErrUserBanned.Message), errors.ErrUserBanned
		}
		// if the ban has expired lift the ban
		_, _ = aus.UserRepo.UpdateUser(ctx, usr.ID, map[string]interface{}{
			"Banned":     false,
			"BanReason":  nil,
			"BanExpires": nil,
		})
	}
	// setup active org id
	now := time.Now()
	updatedUsr, err := aus.UserRepo.UpdateUser(ctx, usr.ID, map[string]interface{}{
		"LastLoginAt": now,
	})
	if err != nil {
		logger.ErrorCtx(ctx, "could not update user last login at", err, nil)
		return dtos.InternalErrMS[accesstokendtos.TokenResponse](err.Error()), err
	}

	sessionID := models.NewSecureId()
	tokens, err := aus.SesSvc.CreateSession(ctx, sessionID, usr.Role.S(), usr.ID, &models.SessionOpt{
		ClearSession: aus.Config != nil && aus.Config.SingleSession,
		DeviceToken:  input.DeviceToken,
	})
	if err != nil {
		return dtos.InternalErrMS[accesstokendtos.TokenResponse](err.Error()), err
	}
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
		UserData:   *updatedUsr,
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
		UserData:   *usr,
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

	return aus.VSvc.SendVerification(ctx, input.Email, models.PurposePasswordReset, &interfaces1.VerOpt{UserId: usr.ID})
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
