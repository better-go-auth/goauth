package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/birukbelay/gocmn/src/logger"
	"github.com/birukbelay/gocmn/src/resp_const"

	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	errors "github.com/better-go-auth/goauth/src/common/error"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/providers/hasher"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
)

// RegisterWithEmail (acc-01) , [AccountStatus], set(pwd,)
func (aus Service) RegisterWithEmail(ctx context.Context, input models.RegisterClientInput) (res dtos.GResp[models.User], eror error) {
	// Check if the email already exists
	usr, err := aus.userRepo.GetUserByEmail(ctx, input.Email)
	if err == nil && usr != nil {
		// If the User is still pending verification, throw error
		// todo create a time out
		if usr.AccountStatus != enums.AccountPendingVerification {
			return dtos.BadReqC[models.User](resp_const.UserExists), resp_const.UserExistError
		}
	}

	hash, err := hasher.BcryptCreateHash(input.Password)
	if err != nil {
		return dtos.InternalErrMS[models.User]("Hashing Error"), err
	}

	var createdUser *models.User
	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		existingUser, getErr := aus.userRepo.GetUserByEmail(txCtx, input.Email)
		if getErr == nil && existingUser != nil {
			// Update pending verification user
			updated, err := aus.userRepo.UpdateUser(txCtx, existingUser.ID, map[string]interface{}{
				"password":       hash,
				"first_name":     input.FirstName,
				"last_name":      input.LastName,
				"account_status": enums.AccountPendingVerification,
				// is this ptr or actual value
				"role":   enums.User.S(),
				"active": false,
			})
			if err != nil {
				return err
			}
			createdUser = updated
		} else {
			newUser := &models.User{
				UserDto: models.UserDto{
					FirstName:     input.FirstName,
					LastName:      input.LastName,
					Email:         &input.Email,
					Password:      hash,
					Role:          enums.User,
					AccountStatus: enums.AccountPendingVerification,
					Active:        new(bool), // false
				},
			}
			created, err := aus.userRepo.CreateUser(txCtx, newUser)
			if err != nil {
				logger.LogTrace("error crating", err)
				return err
			}
			createdUser = created
		}

		now := time.Now()
		// 5. Create email/password account record
		pwdAccount := &models.Account{
			Base:       models.Base{ID: models.NewID(), CreatedAt: &now, UpdatedAt: &now},
			UserID:     createdUser.ID,
			ProviderId: models.ProvCredential,
			AccountID:  input.Email,
			Password:   &hash,
		}
		if _, err := aus.accountRepo.CreateAccount(txCtx, pwdAccount); err != nil {
			// if account already exists for user and provider, update password
			if existingAcc, _ := aus.accountRepo.GetAccountByUserAndProvider(txCtx, createdUser.ID, models.ProvCredential); existingAcc != nil {
				_, _ = aus.accountRepo.UpdateAccount(txCtx, existingAcc.ID, map[string]interface{}{"password": hash})
			} else {
				return fmt.Errorf("authsvc: create account: %w", err)
			}
		}

		_, err = aus.VSvc.SendVerification(txCtx, input.Email, models.PurposeEmailVerification, &serv_interfaces.VerOpt{UserId: createdUser.ID})
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
func (aus Service) VerifyRegisteredUser(ctx context.Context, input VerificationInput) (res dtos.GResp[models.User], eror error) {
	var verifiedUser *models.User
	err := aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		usr, err := aus.userRepo.GetUserByEmail(txCtx, input.Info)
		if err != nil || usr == nil || usr.AccountStatus != enums.AccountPendingVerification {
			return resp_const.InfoOrCodeErr
		}

		// Validate the code
		_, err = aus.VSvc.VerifyCode(txCtx, usr.GetEmail(), models.PurposeEmailVerification, input.Code)
		if err != nil {
			return resp_const.InfoOrCodeErr
		}

		// Update the user's status
		updatedUsr, err := aus.userRepo.UpdateUser(txCtx, usr.ID, map[string]interface{}{
			"account_status": enums.AccountActive,
			"active":         true,
			"email_verified": true,
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
func (aus Service) Login(ctx context.Context, input LoginData) (dtos.GResp[TokenResponse], error) {
	// 1. check the user exists and is active
	usr, err := aus.userRepo.GetUserByEmail(ctx, input.LoginInfo)
	if err != nil || usr == nil || usr.Active == nil || (usr.Active != nil && !*usr.Active) {
		_, _ = hasher.BcryptCreateHash(input.Password) // for security timing protection
		return dtos.BadReqC[TokenResponse](resp_const.EmailOrPassword), resp_const.EmailOrPasswordErr
	}

	// 2. Get password from account record
	account, err := aus.accountRepo.GetAccountByUserAndProvider(ctx, usr.ID, models.ProvCredential)
	if err != nil || account == nil || account.Password == nil {
		_, _ = hasher.BcryptCreateHash(input.Password) // for security timing protection
		return dtos.BadReqC[TokenResponse](resp_const.EmailOrPassword), errors.ErrInvalidCredentials
	}

	// 3. compare the password hash
	valid := hasher.BcryptPasswordsMatch(input.Password, *account.Password)
	if !valid {
		return dtos.BadReqC[TokenResponse](resp_const.EmailOrPassword), resp_const.EmailOrPasswordErr
	}

	// 4. Check ban (after credential check; expired bans are lifted silently)
	if usr.Banned {
		if usr.BanExpires == nil || usr.BanExpires.After(time.Now()) {
			return dtos.BadReqM[TokenResponse](errors.ErrUserBanned.Message), errors.ErrUserBanned
		}
		// if the ban has expired lift the ban
		_, _ = aus.userRepo.UpdateUser(ctx, usr.ID, map[string]interface{}{
			"banned":      false,
			"ban_reason":  nil,
			"ban_expires": nil,
		})
	}
	// setup active org id
	now := time.Now()
	updatedUsr, err := aus.userRepo.UpdateUser(ctx, usr.ID, map[string]interface{}{
		"last_login_at": now,
	})
	if err != nil {
		logger.ErrorCtx(ctx, "could not update user last login at", err, nil)
		return dtos.InternalErrMS[TokenResponse](err.Error()), err
	}

	sessionID := models.NewSecureId()
	tokens, err := aus.SesSvc.CreateSession(ctx, sessionID, usr.Role.S(), usr.ID, &models.SessionOpt{
		ClearSession: true,
		DeviceToken:  input.DeviceToken,
	})
	if err != nil {
		return dtos.InternalErrMS[TokenResponse](err.Error()), err
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

	return dtos.SuccessCreated(TokenResponse{
		AuthTokens: tokens,
		UserData:   *updatedUsr,
	}, 1), nil
}

// ResetToken (acc-04): FIXME to be update with redis: [Role, id]
func (aus Service) ResetToken(ctx context.Context, refreshToken string) (dtos.GResp[TokenResponse], error) {
	// 1. validate the refresh token
	claims, err := jwttoken.ValidateToken(refreshToken, aus.Config.RefreshSecret)
	if err != nil {
		return dtos.BadReqC[TokenResponse](resp_const.InvalidToken), resp_const.InvalidTokenError
	}

	// 2. get the user
	usr, err := aus.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil || usr == nil {
		return dtos.BadReqC[TokenResponse](resp_const.DataNotFound), resp_const.UserNotFoundError
	}

	// 3. get the session that are not blacklisted
	session, err := aus.sessionRepo.GetSessionBySessionID(ctx, claims.SessionID)
	if err != nil || session == nil || session.UserID != claims.UserID || (session.Blacklisted != nil && *session.Blacklisted) {
		return dtos.BadReqC[TokenResponse](resp_const.DataNotFound), resp_const.UserNotFoundError
	}

	// 4. validate the refresh token matches
	valid := hasher.ArgonPasswordsMatch(refreshToken, session.HashedToken)
	if !valid {
		return dtos.BadReqC[TokenResponse](resp_const.TokenDontMatch), resp_const.TokenDontMatchError
	}

	// 5. recreate session tokens
	tokens, err := aus.SesSvc.CreateSession(ctx, claims.SessionID, usr.Role.S(), usr.ID, nil)
	if err != nil {
		return dtos.InternalErrMS[TokenResponse](err.Error()), err
	}

	return dtos.SuccessCreated(TokenResponse{
		AuthTokens: tokens,
		UserData:   *usr,
	}, 1), nil
}

// Logout [-]
func (aus Service) Logout(ctx context.Context, refreshToken string) (dtos.GResp[bool], error) {
	// 1. the jwt token
	claims, err := jwttoken.ValidateToken(refreshToken, aus.Config.RefreshSecret)
	if err != nil {
		return dtos.BadReqC[bool](resp_const.InvalidToken), resp_const.InvalidTokenError
	}

	session, err := aus.sessionRepo.GetSessionBySessionID(ctx, claims.SessionID)
	if err != nil || session == nil {
		return dtos.BadReqC[bool](resp_const.DataNotFound), resp_const.UserNotFoundError
	}

	valid := hasher.ArgonPasswordsMatch(refreshToken, session.HashedToken)
	if !valid {
		return dtos.BadReqC[bool](resp_const.TokenDontMatch), resp_const.TokenDontMatchError
	}

	if err := aus.SesSvc.DeleteSession(ctx, session.SessionId); err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}
	return dtos.SuccessCreated(true, 1), nil
}

// ForgotPwd [ID]
func (aus Service) ForgotPwd(ctx context.Context, input VerifyReqInput) (dtos.GResp[bool], error) {
	usr, err := aus.userRepo.GetUserByEmail(ctx, input.Email)
	if err != nil || usr == nil {
		return dtos.SuccessCreated(true, 0), nil
	}

	return aus.VSvc.SendVerification(ctx, input.Email, models.PurposePasswordReset, &serv_interfaces.VerOpt{UserId: usr.ID})
}

// ResetPwd [ID]
func (aus Service) ResetPwd(ctx context.Context, input PwdResetInput) (dtos.GResp[bool], error) {
	hash, err := hasher.BcryptCreateHash(input.NewPassword)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}

	usr, err := aus.userRepo.GetUserByEmail(ctx, input.Info)
	if err != nil || usr == nil {
		return dtos.BadReqC[bool](resp_const.InfoOrCode), resp_const.InfoOrCodeErr
	}
	// Fetch sessions first so we don't lose their SessionId values upon deletion
	// sessions, fetchErr := generic.DbFetchManyWithOffset[models.Session](aus.Provider.GormConn, ctx, models.Session{UserID: usr.Body.ID}, dtos.PaginationInput{Limit: 10000}, nil)

	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		// 1. Validate the code
		_, err = aus.VSvc.VerifyCode(txCtx, input.Info, models.PurposePasswordReset, input.Code)
		if err != nil {
			return resp_const.InfoOrCodeErr
		}

		// 2. Update user's password
		account, err := aus.accountRepo.GetAccountByUserAndProvider(txCtx, usr.ID, models.ProvCredential)
		if err != nil {
			return err
		}
		if account == nil {
			return errors.ErrInvalidCredentials
		}
		_, err = aus.accountRepo.UpdateAccount(txCtx, account.ID, map[string]interface{}{"password": hash})
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
