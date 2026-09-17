package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/birukbelay/gocmn/src/generic"
	"github.com/birukbelay/gocmn/src/logger"

	"github.com/birukbelay/gocmn/src/resp_const"
	"github.com/birukbelay/gocmn/src/util"
	"github.com/mitchellh/mapstructure"
	"gorm.io/gorm/clause"

	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	errors "github.com/better-go-auth/goauth/src/common/error"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
)

// RegisterWithEmail (acc-01) , [AccountStatus], set(pwd,)
func (aus Service) RegisterWithEmail(ctx context.Context, input models.RegisterClientInput) (res dtos.GResp[models.User], eror error) {
	// Check if the email already exists
	usr, err := generic.DbGetOne[models.User](aus.Provider.GormConn, ctx, models.UserFilter{Email: input.Email}, nil)
	if err == nil {
		// TODO create a timeout
		// If the User is still pending verification, throw error
		if usr.RowsAffected > 0 && usr.Body.AccountStatus != enums.AccountPendingVerification {
			return dtos.BadReqC[models.User](resp_const.UserExists), resp_const.UserExistError
		}
	}
	var userModel models.UserDto
	if err := mapstructure.Decode(input, &userModel); err != nil {
		return dtos.BadReqM[models.User]("Decoding Input Error"), err
	}

	hash, err := crypto.BcryptCreateHash(input.Password)
	if err != nil {
		return dtos.InternalErrMS[models.User]("Hashing Error"), err
	}
	userModel.Password = hash
	userModel.Role = enums.User
	userModel.AccountStatus = enums.AccountPendingVerification
	userModel.Active = new(false)

	var createdUser models.User
	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		user, err := generic.DbUpsertOneAllFields[models.User](gormutil.GetDB(txCtx, aus.Provider.GormConn), ctx, &userModel, []clause.Column{{Name: "email"}}, nil)
		if err != nil {
			logger.LogTrace("error crating", err)
			return err
		}
		createdUser = user.Body
		now := time.Now()
		// 5. Create email/password account record
		pwdAccount := &models.Account{
			Base:       models.Base{ID: models.NewID(), CreatedAt: &now, UpdatedAt: &now},
			UserID:     createdUser.ID,
			ProviderId: models.ProvCredential,
			AccountID:  input.Email,
			Password:   new(hash),
		}
		if _, err := aus.accountRepo.CreateAccount(txCtx, pwdAccount); err != nil {
			return fmt.Errorf("authsvc: create account: %w", err)
		}
		_, err = aus.VSvc.SendVerification(txCtx, input.Email, models.PurposeEmailVerification, &serv_interfaces.VerOpt{UserId: user.Body.ID})
		if err != nil {
			// todo: maybe we skip this error
			return err
		}

		return nil
	})
	if err != nil {
		return dtos.InternalErrMS[models.User]("transaction Error"), err
	}

	return dtos.SuccessCreated(createdUser, 1), nil
}

// VerifyRegisteredUser (acc-01), [id]x
func (aus Service) VerifyRegisteredUser(ctx context.Context, input VerificationInput) (res dtos.GResp[models.User], eror error) {
	var verifiedUser models.User
	err := aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		usr, err := generic.DbGetOne[models.User](gormutil.GetDB(txCtx, aus.Provider.GormConn), ctx, models.UserFilter{Email: input.Info, AccountStatus: enums.AccountPendingVerification}, nil)
		if err != nil {
			return resp_const.InfoOrCodeErr
		}
		// Validate the code, but because this is sign up it is upderted via email
		_, err = aus.VSvc.VerifyCode(txCtx, usr.Body.GetEmail(), models.PurposeEmailVerification, input.Code)
		if err != nil {
			return resp_const.InfoOrCodeErr
		}
		// Update the users status
		updatedUsr, err := generic.DbUpdateByFilter[models.User](gormutil.GetDB(txCtx, aus.Provider.GormConn), ctx, models.UserFilter{Email: input.Info}, models.UserDto{AccountStatus: enums.AccountActive, Active: new(true), EmailVerified: true}, nil)
		if err != nil {
			return err
		}
		verifiedUser = updatedUsr.Body
		return nil
	})
	if err != nil {
		return dtos.InternalErrMS[models.User]("transaction Error"), err
	}

	return dtos.SuccessCreated(verifiedUser, 1), nil
}

// Login (acc-03) [companyId, Role, Password]
func (aus Service) Login(ctx context.Context, input LoginData) (dtos.GResp[TokenResponse], error) {
	// 1. check the user exists, to login the user must be active: with status: verified, companySetup...
	usr, err := generic.DbGetOne[models.User](aus.Provider.GormConn, ctx, models.UserDto{Email: util.Ptr(input.LoginInfo), Active: util.Ptr(true)}, &generic.Opt{Debug: false})
	if err != nil || usr.RowsAffected < 1 {
		_, _ = crypto.BcryptCreateHash(input.Password) // for security reasons
		return dtos.BadReqC[TokenResponse](resp_const.EmailOrPassword), resp_const.EmailOrPasswordErr
	}

	// 2. Get password from account record
	account, err := aus.accountRepo.GetAccountByUserAndProvider(ctx, usr.Body.ID, models.ProvCredential)
	if err != nil || account == nil || account.Password == nil {
		_, _ = crypto.BcryptCreateHash(input.Password) // for security reasons
		return dtos.BadReqC[TokenResponse](resp_const.EmailOrPassword), errors.ErrInvalidCredentials
	}

	// 2. compare the password hash
	valid := crypto.BcryptPasswordsMatch(input.Password, *account.Password)
	if !valid {
		return dtos.BadReqC[TokenResponse](resp_const.EmailOrPassword), resp_const.EmailOrPasswordErr
	}

	// 4. Check ban (after credential check; expired bans are lifted silently)
	if usr.Body.Banned {
		if usr.Body.BanExpires == nil || usr.Body.BanExpires.After(time.Now()) {
			return dtos.BadReqM[TokenResponse](errors.ErrUserBanned.Message), errors.ErrUserBanned
		}
		// if the ban has expired lift the ban
		_, _ = generic.DbUpdateByFilter[models.User](aus.Provider.GormConn, ctx, models.UserFilter{ID: usr.Body.ID}, map[string]any{"banned": false, "ban_reason": nil, "ban_expires": nil}, nil)
	}

	// we use map to set nul to some fields like active org id
	userUpdate := map[string]any{
		"last_login_at": new(time.Now()),
	}

	updatedUsr, err := generic.DbUpdateByFilter[models.User](aus.Provider.GormConn, ctx, models.UserFilter{ID: usr.Body.ID}, userUpdate, nil)
	if err != nil {
		logger.ErrorCtx(ctx, "couldnot update user last login at", err, nil)
		return dtos.InternalErrMS[TokenResponse](err.Error()), err
	}

	sessionID := models.NewSecureId()
	tokens, err := aus.SesSvc.CreateSession(ctx, sessionID, usr.Body.Role.S(), usr.Body.ID, &models.SessionOpt{ClearSession: true, DeviceToken: input.DeviceToken})
	if err != nil {
		return dtos.InternalErrMS[TokenResponse](err.Error()), err
	}

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
		UserData:   updatedUsr.Body,
	}, updatedUsr.RowsAffected), nil
}

// ResetToken (acc-04): FIXME to be update with redis: [Role, id]
func (aus Service) ResetToken(ctx context.Context, refreshToken string) (dtos.GResp[TokenResponse], error) {
	// 1. validate the refresh token
	claims, ok, err := crypto.Valid(refreshToken, aus.Config.RefreshSecret)
	if !ok || (err != nil) {
		return dtos.BadReqC[TokenResponse](resp_const.InvalidToken), resp_const.InvalidTokenError
	}
	// 2. get the user
	usr, err := generic.DbGetOneByID[models.User](aus.Provider.GormConn, ctx, claims.UserId, nil)
	if err != nil {
		return dtos.BadReqC[TokenResponse](resp_const.DataNotFound), resp_const.UserNotFoundError
	}
	// 3. get the session that are not blacklisted
	session, err := generic.DbGetOne[models.Session](aus.Provider.GormConn, ctx, models.Session{UserID: claims.UserId, SessionId: claims.SessionId, Blacklisted: util.Ptr(false)}, nil)
	if err != nil {
		return dtos.BadReqC[TokenResponse](resp_const.DataNotFound), resp_const.UserNotFoundError
	}

	// 4. validate the refresh token is the same
	valid := crypto.ArgonPasswordsMatch(refreshToken, session.Body.HashedToken)
	if !valid {
		return dtos.BadReqC[TokenResponse](resp_const.TokenDontMatch), resp_const.TokenDontMatchError
	}

	// 5. update the sessions, incase the users role is changed we need to user the users new role
	tokens, err := aus.SesSvc.CreateSession(ctx, claims.SessionId, usr.Body.Role.S(), usr.Body.ID, nil)
	if err != nil {
		return dtos.InternalErrMS[TokenResponse](err.Error()), err
	}

	return dtos.SuccessCreated(TokenResponse{
		AuthTokens: tokens,
		UserData:   usr.Body,
	}, 1), nil
}

// Logout [-]
func (aus Service) Logout(ctx context.Context, refreshToken string) (dtos.GResp[bool], error) {
	// 1. the jwt token
	claims, ok, err := crypto.Valid(refreshToken, aus.Config.RefreshSecret)
	if !ok || (err != nil) {
		return dtos.BadReqC[bool](resp_const.InvalidToken), resp_const.InvalidTokenError
	}
	// 2. get the session from the database
	session, err := generic.DbGetOne[models.Session](aus.Provider.GormConn, ctx, models.Session{SessionId: claims.SessionId}, nil)
	if err != nil {
		return dtos.BadReqC[bool](resp_const.DataNotFound), resp_const.UserNotFoundError
	}
	// 3. verify the refresh token is the same
	valid := crypto.ArgonPasswordsMatch(refreshToken, session.Body.HashedToken)
	if !valid {
		return dtos.BadReqC[bool](resp_const.TokenDontMatch), resp_const.TokenDontMatchError
	}
	// 4. delete the session
	if err := aus.SesSvc.DeleteSession(ctx, session.Body.SessionId); err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}
	return dtos.SuccessCreated(true, 1), nil
}

// ForgotPwd [ID]
func (aus Service) ForgotPwd(ctx context.Context, input VerifyReqInput) (dtos.GResp[bool], error) {
	usr, err := generic.DbGetOne[models.User](aus.Provider.GormConn, ctx, models.UserFilter{Email: input.Email}, nil)
	if err != nil {
		return dtos.SuccessCreated(true, 0), nil
	}

	return aus.VSvc.SendVerification(ctx, input.Email, models.PurposePasswordReset, &serv_interfaces.VerOpt{UserId: usr.Body.GetID()})
}

// ResetPwd [ID]
func (aus Service) ResetPwd(ctx context.Context, input PwdResetInput) (dtos.GResp[bool], error) {
	hash, err := crypto.BcryptCreateHash(input.NewPassword)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}

	// 1. Get the user,
	usr, err := generic.DbGetOne[models.User](aus.Provider.GormConn, ctx, models.UserFilter{Email: input.Info}, &generic.Opt{Preloads: []string{"Sessions"}})
	if err != nil {
		return dtos.BadReqC[bool](resp_const.InfoOrCode), resp_const.InfoOrCodeErr
	}
	// Fetch sessions first so we don't lose their SessionId values upon deletion
	// sessions, fetchErr := generic.DbFetchManyWithOffset[models.Session](aus.Provider.GormConn, ctx, models.Session{UserID: usr.Body.ID}, dtos.PaginationInput{Limit: 10000}, nil)

	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		// 2. Validate the code
		_, err = aus.VSvc.VerifyCode(txCtx, input.Info, models.PurposePasswordReset, input.Code)
		if err != nil {
			return resp_const.InfoOrCodeErr
		}
		// 4. Update the users password
		account, err := aus.accountRepo.GetAccountByUserAndProvider(txCtx, usr.Body.ID, models.ProvCredential)
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
		// Clean up token
		if err := aus.VSvc.DeleteByIdentifier(txCtx, input.Info, models.PurposePasswordReset); err != nil {
			return fmt.Errorf("authsvc: Deleting verification code errors: %w", err)
		}

		// delete all the user's sessions:
		err = aus.SesSvc.DeleteAllUserSessions(txCtx, usr.Body.ID)
		if err != nil {
			logger.LogError("Deleting user sessions errors", err.Error())
		}
		return nil
	})
	if err != nil {
		return dtos.InternalErrMS[bool]("transaction Error"), err
	}

	return dtos.SuccessCreated(true, usr.RowsAffected), nil
}
