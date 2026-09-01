package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/birukbelay/gocmn/src/generic"
	"github.com/birukbelay/gocmn/src/logger"

	"github.com/birukbelay/gocmn/src/provider/db/redis"
	"github.com/birukbelay/gocmn/src/resp_const"
	"github.com/birukbelay/gocmn/src/util"
	"github.com/mitchellh/mapstructure"
	"github.com/oklog/ulid/v2"
	"gorm.io/gorm/clause"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/config"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/providers"
)

type Service[T models.IntUsr] struct {
	Config   *config.EnvConfig
	Provider *providers.IProviderS
}

func NewAdminAuthServH[T models.IntUsr](conf *config.EnvConfig, genServ *providers.IProviderS) *Service[T] {
	return &Service[T]{
		Config:   conf,
		Provider: genServ,
	}
}

// Register (acc-01) , [AccountStatus], set(pwd,)
func (aus Service[T]) Register(ctx context.Context, input models.RegisterClientInput) (res dtos.GResp[bool], eror error) {
	//Check if the email already exists
	usr, err := generic.DbGetOne[T](aus.Provider.GormConn, ctx, models.UserFilter{Email: input.Email}, nil)
	//if the user already exists
	// logger.LogTrace("usr", usr)
	if err == nil {
		//TODO create a timeout
		//If the User is still pending verification, throw error
		if usr.RowsAffected > 0 && usr.Body.GetStatus() != enums.AccountPendingVerification {
			//FIXME Send password or email wrong depending on the scenario
			return dtos.BadReqC[bool](resp_const.UserExists), resp_const.UserExistError
		}
	}
	//TODO: verify the Email
	//user userDto here
	var userModel models.UserDto
	if err := mapstructure.Decode(input, &userModel); err != nil {
		return dtos.BadReqM[bool]("Decoding Input Error"), err
	}

	hash, err := crypto.BcryptCreateHash(input.Password)
	if err != nil {
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}
	userModel.Password = hash
	userModel.Role = enums.User
	userModel.AccountStatus = enums.AccountPendingVerification
	userModel.Active = util.Ptr(false)

	tx := aus.Provider.GormConn.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			res, eror = dtos.InternalErrMS[bool]("Transaction error"), errors.New("transaction error")
		}
	}()
	if err := tx.Error; err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}

	// []string{"Password", "VerificationCodeHash", "VerificationCodeExpire", "AccountStatus", "Role", "Active"}
	user, err := generic.DbUpsertOneAllFields[T](tx, ctx, &userModel, []clause.Column{{Name: "email"}}, nil)
	if err != nil {
		tx.Rollback()
		logger.LogTrace("error crating", err)
		return dtos.InternalErrMS[bool]("creating Error"), err
	}
	resp, err := aus.UTIL_SendEmailVerification(tx, ctx, input.Email, models.GetID(user.Body), models.UpsertByEmail, models.SignupVerification)
	if err != nil {
		tx.Rollback()
		return dtos.InternalErrMS[bool]("Sending Email error"), err
	}
	commit := tx.Commit()
	if commit.Error != nil {
		return dtos.InternalErrMS[bool](commit.Error.Error()), commit.Error
	}

	return resp, err

}

// VerifyRegisteredUser (acc-01), [id]x
func (aus Service[T]) VerifyRegisteredUser(ctx context.Context, input VerificationInput) (res dtos.GResp[bool], eror error) {
	//Check if the email already exists

	tx := aus.Provider.GormConn.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			eror = fmt.Errorf("panic occurred: %v", r)
			res = dtos.InternalErrMS[bool]("transaction error")
		}
	}()
	if err := tx.Error; err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}

	usr, err := generic.DbGetOne[T](tx, ctx, models.UserFilter{Email: input.Info, AccountStatus: enums.AccountPendingVerification}, nil)
	if err != nil {
		tx.Rollback()
		return dtos.BadReqC[bool](resp_const.InfoOrCode), resp_const.InfoOrCodeErr
	}
	//Validate the code, but because this is sign up it is upderted via email
	codeValid := aus.VerifyCode(tx, ctx, usr.Body.GetInfo(), input.Code, models.UpsertByEmail)
	if !codeValid {
		tx.Rollback()
		return dtos.BadReqC[bool](resp_const.InfoOrCode), resp_const.InfoOrCodeErr
	}

	//Update the users status
	user, err := generic.DbUpdateByFilter[T](tx, ctx, models.UserFilter{Email: input.Info}, models.UserDto{AccountStatus: enums.AccountActive, Active: util.Ptr(true)}, nil)
	if err != nil {
		tx.Rollback()
		// cmn.LogTrace("error crating", err)
		return dtos.InternalErrMS[bool]("creating Error"), err
	}
	//TODO: invalidate the code
	commit := tx.Commit()
	if commit.Error != nil {
		return dtos.InternalErrMS[bool](commit.Error.Error()), commit.Error
	}

	// tasks.EnqueueAuditActivityLog(ctx, aus.Provider.QueueClient, aus.Provider.GormConn, tasks.AuditActivityLogPayload{
	// 	CompanyID:   "",
	// 	UserID:      models.GetID(user.Body),
	// 	Action:      "VERIFY_REGISTERED_USER",
	// 	EntityType:  "user",
	// 	EntityID:    models.GetID(user.Body),
	// 	Summary:     "Email verified successfully",
	// 	Changes:     tasks.ToJSON(user.Body),
	// 	LogAudit:    true,
	// 	LogActivity: true,
	// })

	return dtos.SuccessS(true, user.RowsAffected), nil
}

// Login (acc-03) [companyId, Role, Password]
func (aus Service[T]) Login(ctx context.Context, input LoginData) (dtos.GResp[TokenResponse], error) {
	//1. check the user exists, to login the user must be active: with status: verified, companySetup...
	usr, err := generic.DbGetOne[T](aus.Provider.GormConn, ctx, models.UserDto{Email: util.Ptr(input.LoginInfo), Active: util.Ptr(true)}, &generic.Opt{Debug: false})
	if err != nil || usr.RowsAffected < 1 {
		return dtos.BadReqC[TokenResponse](resp_const.EmailOrPassword), resp_const.EmailOrPasswordErr
	}

	//2. compare the password hash
	valid := crypto.BcryptPasswordsMatch(input.Password, usr.Body.GetPwd())
	if !valid {
		return dtos.BadReqC[TokenResponse](resp_const.EmailOrPassword), resp_const.EmailOrPasswordErr
	}

	var companyID string
	userRole := string(usr.Body.GetRole())

	userUpdate := map[string]interface{}{
		"last_login_at": util.Ptr(time.Now()),
	}

	//TODO: update the active membership, manually or on a post script
	// member, err := aus.getUserMembership(ctx, usr.Body.GetID())
	// if err != nil {
	// 	userUpdate["company_id"] = nil
	// 	//if user is not part of any membership: make him unverified
	// 	userUpdate["role"] = enums.UnverifiedUser
	// 	userUpdate["company_role_id"] = nil
	// 	userUpdate["company_role_name"] = ""
	// } else {
	// 	userUpdate["role"] = enums.Role(member.RoleGroup) //a user could have a different role in different companies
	// 	userUpdate["company_role_id"] = member.CompanyRoleID
	// 	userUpdate["company_role_name"] = member.CompanyRoleName
	// 	userUpdate["company_id"] = member.CompanyID
	// 	if member.Status == enums.MembershipBlocked {
	// 		companyID = ""
	// 		userUpdate["company_id"] = nil
	// 	} else {
	// 		companyID = member.CompanyID
	// 	}
	// 	if member.RoleGroup != "" {
	// 		userRole = string(member.RoleGroup)
	// 	}
	// }

	//Update the users data:
	// - current active company,
	// - current active companies role id,
	updatedUsr, err := generic.DbUpdateByFilter[T](aus.Provider.GormConn, ctx, models.UserFilter{ID: usr.Body.GetID()}, userUpdate, nil)
	if err != nil {
		logger.ErrorCtx(ctx, "couldnot update user last login at", err, nil)
		return dtos.InternalErrMS[TokenResponse](err.Error()), err
	}

	sessionID := ulid.Make().String()
	tokens, err := aus.UTIL_MakeSession(ctx, sessionID, userRole, usr.Body.GetID(), companyID, input.DeviceToken, &SessionOpt{ClearSession: true})
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

	return dtos.SuccessS(TokenResponse{
		AuthTokens: *tokens,
		UserData:   updatedUsr.Body,
	}, updatedUsr.RowsAffected), nil

}

// func (aus Service[T]) getUserMembership(ctx context.Context, userID string) (models.CompanyMember, error) {
// 	memberResp, activeMembershipErr := generic.DbGetOne[models.CompanyMember](aus.Provider.GormConn, ctx, models.CompanyMemberDto{
// 		UserID:    userID,
// 		IsCurrent: util.Ptr(true),
// 		Status:    enums.MembershipActive},
// 		nil)
// 	if activeMembershipErr != nil {
// 		//FIND ANY MEMBERSHIP
// 		anyMembership, err := generic.DbGetOne[models.CompanyMember](aus.Provider.GormConn, ctx, models.CompanyMemberDto{
// 			UserID: userID,
// 			Status: enums.MembershipActive},
// 			nil)
// 		if err != nil {
// 			return models.CompanyMember{}, err
// 		}
// 		//Update the IsCurrent to true
// 		_, err = generic.DbUpdateOneById[models.CompanyMember](aus.Provider.GormConn, ctx, anyMembership.Body.ID, models.CompanyMemberDto{IsCurrent: util.Ptr(true)}, nil)
// 		if err != nil {
// 			// return models.CompanyMember{}, err
// 		}

// 		return anyMembership.Body, nil

// 	}
// 	return memberResp.Body, nil
// }

// ResetToken (acc-04): FIXME to be update with redis: [Role, id]
func (aus Service[T]) ResetToken(ctx context.Context, refreshToken string) (dtos.GResp[TokenResponse], error) {
	//1. validate the refresh token
	claims, ok, err := crypto.Valid(refreshToken, aus.Config.RefreshSecret)
	if !ok || (err != nil) {
		return dtos.BadReqC[TokenResponse](resp_const.InvalidToken), resp_const.InvalidTokenError
	}
	// 2. get the user
	usr, err := generic.DbGetOneByID[T](aus.Provider.GormConn, ctx, claims.UserId, nil)
	if err != nil {
		return dtos.BadReqC[TokenResponse](resp_const.DataNotFound), resp_const.UserNotFoundError
	}
	// 3. get the session that are not blacklisted
	session, err := generic.DbGetOne[models.Session](aus.Provider.GormConn, ctx, models.Session{UserId: claims.UserId, SessionId: claims.SessionId, Blacklisted: util.Ptr(false)}, nil)
	if err != nil {
		return dtos.BadReqC[TokenResponse](resp_const.DataNotFound), resp_const.UserNotFoundError
	}

	// 4. validate the refresh token is the same
	valid := crypto.ArgonPasswordsMatch(refreshToken, session.Body.HashedRefresh)
	if !valid {
		return dtos.BadReqC[TokenResponse](resp_const.TokenDontMatch), resp_const.TokenDontMatchError
	}

	// // TODO: update the active membership
	// var currentMember models.CompanyMember
	// mErr := aus.Provider.GormConn.Where("user_id = ? AND company_id = ?", claims.UserId, claims.CompanyId).First(&currentMember).Error
	// if claims.CompanyId != "" {
	// 	if mErr != nil {
	// 		return dtos.BadReqM[TokenResponse]("user is not a member of this company"), mErr
	// 	}
	// 	if currentMember.Status != enums.MembershipActive {
	// 		return dtos.BadReqM[TokenResponse]("user is blocked from this company"), errors.New("user is blocked from this company")
	// 	}
	// }
	userRole := string(usr.Body.GetRole())
	// if mErr == nil && currentMember.RoleGroup != "" {
	// 	userRole = string(currentMember.RoleGroup)
	// }

	//5. update the sessions, incase the users role is changed we need to user the users new role
	tokens, err := aus.UTIL_MakeSession(ctx, claims.SessionId, userRole, models.GetID(usr.Body), claims.CompanyId, "", nil)
	if err != nil {
		return dtos.InternalErrMS[TokenResponse](err.Error()), err
	}

	return dtos.SuccessS(TokenResponse{
		AuthTokens: *tokens,
		UserData:   usr.Body,
	}, 1), nil

}

// Logout [-]
func (aus Service[T]) Logout(ctx context.Context, refreshToken string) (dtos.GResp[bool], error) {

	//1. the jwt token
	claims, ok, err := crypto.Valid(refreshToken, aus.Config.RefreshSecret)
	if !ok || (err != nil) {
		return dtos.BadReqC[bool](resp_const.InvalidToken), resp_const.InvalidTokenError
	}
	// 2. get the session from the database
	session, err := generic.DbGetOne[models.Session](aus.Provider.GormConn, ctx, models.Session{SessionId: claims.SessionId}, nil)
	if err != nil {
		return dtos.BadReqC[bool](resp_const.DataNotFound), resp_const.UserNotFoundError
	}
	//3. verify the refresh token is the same
	valid := crypto.ArgonPasswordsMatch(refreshToken, session.Body.HashedRefresh)
	if !valid {
		return dtos.BadReqC[bool](resp_const.TokenDontMatch), resp_const.TokenDontMatchError
	}
	//4. delete the session
	resp, eror := generic.DbDeleteOneById[models.Session](aus.Provider.GormConn, ctx, session.Body.ID, nil)
	if eror != nil {
		return dtos.InternalErrMS[bool](eror.Error()), eror
	}
	err = redis.BlacklistSession(aus.Provider.KeyValServ, ctx, session.Body.SessionId)
	return dtos.SuccessS(true, resp.RowsAffected), nil
}

// ForgotPwd [ID]
func (aus Service[T]) ForgotPwd(ctx context.Context, input VerifyReqInput) (dtos.GResp[bool], error) {
	usr, err := generic.DbGetOne[T](aus.Provider.GormConn, ctx, models.UserFilter{Email: input.Email}, nil)

	if err != nil {
		return dtos.SuccessS(true, 0), nil
	}
	// tasks.EnqueueAuditActivityLog(ctx, aus.Provider.QueueClient, aus.Provider.GormConn, tasks.AuditActivityLogPayload{
	// 	CompanyID:   "",
	// 	UserID:      models.GetID(usr.Body),
	// 	Action:      "FORGOT_PASSWORD",
	// 	EntityType:  "user",
	// 	EntityID:    models.GetID(usr.Body),
	// 	Summary:     "Requested password reset link",
	// 	LogAudit:    true,
	// 	LogActivity: true,
	// })

	return aus.UTIL_SendEmailVerification(
		aus.Provider.GormConn, ctx,
		input.Email, models.GetID(usr.Body), models.UpsertByEmail, models.PasswordReset)
}

// ResetPwd [ID]
func (aus Service[T]) ResetPwd(ctx context.Context, input PwdResetInput) (dtos.GResp[bool], error) {
	tx := aus.Provider.GormConn.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()
	if err := tx.Error; err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}

	//1. Get the user
	usr, err := generic.DbGetOne[T](tx, ctx, models.UserFilter{Email: input.Info}, nil)
	if err != nil {
		tx.Rollback()
		return dtos.BadReqC[bool](resp_const.InfoOrCode), resp_const.InfoOrCodeErr
	}
	//2. Validate the code
	codeValid := aus.VerifyCode(tx, ctx, input.Info, input.Code, models.UpsertByEmail)
	if !codeValid {
		tx.Rollback()
		return dtos.BadReqC[bool](resp_const.InfoOrCode), resp_const.InfoOrCodeErr
	}
	//3. hash the new Password
	hash, err := crypto.BcryptCreateHash(input.NewPassword)
	if err != nil {
		tx.Rollback()
		return dtos.InternalErrMS[bool]("Hashing Error"), err
	}
	// Fetch sessions first so we don't lose their SessionId values upon deletion
	sessions, fetchErr := generic.DbFetchManyWithOffset[models.Session](tx, ctx, models.Session{UserId: models.GetID(usr.Body)}, dtos.PaginationInput{Limit: 10000}, nil)

	//4. Update the users password
	user, err := generic.DbUpdateByFilter[T](tx, ctx, models.UserFilter{Email: input.Info}, models.UserDto{Password: hash}, nil)
	if err != nil {
		tx.Rollback()
		return dtos.InternalErrMS[bool]("creating Error"), err
	}
	//delete all the user's sessions
	_, err = generic.DbDeleteByFilter[models.Session](tx, ctx, models.Session{UserId: models.GetID(usr.Body)}, nil)
	if err != nil {
		logger.LogError("Deleting user sessions errors", err.Error())
	}

	commit := tx.Commit()
	if commit.Error != nil {
		return dtos.InternalErrMS[bool](commit.Error.Error()), commit.Error
	}

	// Blacklist the fetched sessions in Redis
	if fetchErr == nil {
		for _, val := range sessions.Body {
			_ = redis.BlacklistSession(aus.Provider.KeyValServ, ctx, val.SessionId)
		}
	}

	// tasks.EnqueueAuditActivityLog(ctx, aus.Provider.QueueClient, aus.Provider.GormConn, tasks.AuditActivityLogPayload{
	// 	CompanyID:   "",
	// 	UserID:      models.GetID(usr.Body),
	// 	Action:      "RESET_PASSWORD",
	// 	EntityType:  "user",
	// 	EntityID:    models.GetID(usr.Body),
	// 	Summary:     "Password reset completed successfully",
	// 	Changes:     tasks.Diff(usr.Body, user.Body),
	// 	LogAudit:    true,
	// 	LogActivity: false,
	// })

	return dtos.SuccessS(true, user.RowsAffected), nil
}

// func (aus Service[T]) ChangeActiveCompany(ctx context.Context, userId string, input ChangeActiveCompanyInput) (dtos.GResp[TokenResponse], error) {
// 	// 1. Verify membership
// 	var targetMember models.CompanyMember
// 	err := aus.Provider.GormConn.Where("user_id = ? AND company_id = ?", userId, input.CompanyID).First(&targetMember).Error
// 	if err != nil {
// 		return dtos.NotFoundErrS[TokenResponse]("User is not a member of this company"), err
// 	}
// 	if targetMember.Status == enums.MembershipBlocked {
// 		return dtos.BadReqM[TokenResponse]("User is blocked from this company"), errors.New("blocked from company")
// 	}

// 	// 2. Begin transaction to update current status
// 	tx := aus.Provider.GormConn.Begin()
// 	if tx.Error != nil {
// 		return dtos.InternalErrMS[TokenResponse](tx.Error.Error()), tx.Error
// 	}

// 	// Set all memberships for this user to is_current = false
// 	if err := tx.Model(&models.CompanyMember{}).Where(models.CompanyMemberFilter{UserID: userId}).Update("is_current", false).Error; err != nil {
// 		tx.Rollback()
// 		return dtos.InternalErrMS[TokenResponse]("Failed to reset active company"), err
// 	}

// 	// Set target membership to is_current = true
// 	if err := tx.Model(&models.CompanyMember{}).Where(models.CompanyMemberFilter{UserID: userId, CompanyID: input.CompanyID}).Update("is_current", true).Error; err != nil {
// 		tx.Rollback()
// 		return dtos.InternalErrMS[TokenResponse]("Failed to set active company"), err
// 	}

// 	// Fetch user details for response
// 	usr, err := generic.DbGetOneByID[T](tx, ctx, userId, nil)
// 	if err != nil {
// 		tx.Rollback()
// 		return dtos.NotFoundErrS[TokenResponse]("User not found"), err
// 	}

// 	// 3. Generate new session/token
// 	sessionID := ulid.Make().String()
// 	userRole := string(usr.Body.GetRole())
// 	if targetMember.RoleGroup != "" {
// 		userRole = string(targetMember.RoleGroup)
// 	}

// 	// Commit transaction before generating/saving session to avoid deadlock
// 	if err := tx.Commit().Error; err != nil {
// 		return dtos.InternalErrMS[TokenResponse](err.Error()), err
// 	}

// 	tokens, err := aus.UTIL_MakeSession(ctx, sessionID, userRole, userId, input.CompanyID, "", &SessionOpt{ClearSession: true})
// 	if err != nil {
// 		return dtos.InternalErrMS[TokenResponse](err.Error()), err
// 	}

// 	tasks.EnqueueAuditActivityLog(ctx, aus.Provider.QueueClient, aus.Provider.GormConn, tasks.AuditActivityLogPayload{
// 		CompanyID:   input.CompanyID,
// 		UserID:      userId,
// 		Action:      "CHANGE_ACTIVE_COMPANY",
// 		EntityType:  "user",
// 		EntityID:    userId,
// 		Summary:     "Switched active organization context",
// 		LogAudit:    true,
// 		LogActivity: true,
// 	})

// 	return dtos.SuccessS(TokenResponse{
// 		AuthTokens: *tokens,
// 		UserData:   usr.Body,
// 	}, 1), nil
// }
