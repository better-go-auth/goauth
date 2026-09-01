package profile

import (
	"context"
	"strings"

	ICrypt "github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	sql_db "github.com/birukbelay/gocmn/src/generic"
	"github.com/birukbelay/gocmn/src/provider/db/redis"
	ICnst "github.com/birukbelay/gocmn/src/resp_const"

	"github.com/better-go-auth/goauth/src/app/account/interfaces"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers"
)

type Service[T models.IntUsr] struct {
	ProvServ *providers.IProviderS
}

func NewProfileServH[T models.IntUsr](genServ *providers.IProviderS) *Service[T] {
	return &Service[T]{
		ProvServ: genServ,
	}
}

// ChangePassword .
func (aus *Service[T]) ChangePassword(ctx context.Context, userId, sessionId string, input models.PasswordUpdateDto) (dtos.GResp[T], error) {
	resp, err := sql_db.DbGetOne[T](aus.ProvServ.GormConn, ctx, models.UserFilter{ID: userId}, nil)
	if err != nil {
		return resp, err
	}
	valid := ICrypt.BcryptPasswordsMatch(input.OldPassword, resp.Body.GetPwd())
	if !valid {
		return dtos.BadReqM[T](ICnst.PasswordDontMatch.Msg()), ICnst.PwdDontMatch
	}
	hash, err := ICrypt.BcryptCreateHash(input.NewPassword)
	if err != nil {
		return dtos.InternalErrMS[T]("Hashing Error"), err
	}
	updateResp, err := sql_db.DbUpdateOneById[T](aus.ProvServ.GormConn, ctx, userId, models.UserDto{Password: hash}, nil)
	if err != nil {
		return dtos.InternalErrMS[T]("Update Error"), err
	}

	_, err = sql_db.DbDeleteByFilter[models.Session](aus.ProvServ.GormConn, ctx, models.Session{UserId: userId, SessionId: sessionId}, nil)
	if err != nil {
		return dtos.InternalErrMS[T]("Session Removing error"), err
	}
	_ = redis.BlacklistSession(aus.ProvServ.KeyValServ, ctx, sessionId)
	//blacklist all the session
	sessions, err := sql_db.DbFetchManyWithOffset[models.Session](aus.ProvServ.GormConn, ctx, models.Session{UserId: userId}, dtos.PaginationInput{Limit: 10000}, nil)
	if err != nil {

	}
	for _, val := range sessions.Body {
		err = redis.BlacklistSession(aus.ProvServ.KeyValServ, ctx, val.SessionId)
	}
	// tasks.EnqueueAuditActivityLog(ctx, aus.ProvServ.QueueClient, aus.ProvServ.GormConn, tasks.AuditActivityLogPayload{
	// 	CompanyID:   "",
	// 	UserID:      userId,
	// 	Action:      "CHANGE_PASSWORD",
	// 	EntityType:  "user",
	// 	EntityID:    userId,
	// 	Summary:     "Password changed successfully",
	// 	Changes:     `{"password": {"old": "[redacted]", "new": "[redacted]"}}`,
	// 	LogAudit:    true,
	// 	LogActivity: true,
	// })
	return updateResp, err
}

// SendChangeEmail .params{userId: from token}
func (aus *Service[T]) SendChangeEmail(ctx context.Context, userId string, input models.ChangeEmailReqDto) (dtos.GResp[bool], error) {
	//1.get ther user
	resp, err := sql_db.DbGetOne[T](aus.ProvServ.GormConn, ctx, models.UserFilter{ID: userId}, nil)
	if err != nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}
	//2.check if his passowrd is correct
	valid := ICrypt.BcryptPasswordsMatch(input.Password, resp.Body.GetPwd())
	if !valid {
		return dtos.BadReqM[bool](ICnst.InfoOrCode.Msg()), ICnst.InfoOrCodeErr
	}
	//3. check if the email already exists
	_, err = sql_db.DbGetOne[T](aus.ProvServ.GormConn, ctx, models.UserFilter{Email: input.NewEmail}, nil)
	if err == nil {
		return dtos.BadReqC[bool](ICnst.EmailExists), ICnst.EmailExistsErr
	}
	// tasks.EnqueueAuditActivityLog(ctx, aus.ProvServ.QueueClient, aus.ProvServ.GormConn, tasks.AuditActivityLogPayload{
	// 	CompanyID:   "",
	// 	UserID:      userId,
	// 	Action:      "SEND_CHANGE_EMAIL",
	// 	EntityType:  "user",
	// 	EntityID:    userId,
	// 	Summary:     fmt.Sprintf("Requested to change email address to %s", input.NewEmail),
	// 	Changes:     fmt.Sprintf(`{"new_email": "%s"}`, input.NewEmail),
	// 	LogAudit:    true,
	// 	LogActivity: true,
	// })
	// return aus.UTIL_SendVerification(ctx, input.NewEmail, models.GetID(resp.Body), models.ChangeEmail)
	return aus.ProvServ.VerificatinService.SendVerification(ctx, input.NewEmail, models.PurposeChangeEmail, &interfaces.VerOpt{UserId: resp.Body.GetID()})
}

// VerifyChangeEmail .change the users email
func (aus *Service[T]) VerifyChangeEmail(ctx context.Context, userId string, input models.VerifyEmailDto) (dtos.GResp[bool], error) {
	//1. Get the user
	resp, err := sql_db.DbGetOne[T](aus.ProvServ.GormConn, ctx, models.UserFilter{ID: userId}, nil)
	if err != nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}
	//2. Validate the code
	// codeValid, email := aus.VerifyCode(ctx, models.GetID(resp.Body), input.Code)
	// if !codeValid {
	// 	return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	// }
	//2. Validate the code
	codeValid, err := aus.ProvServ.VerificatinService.VerifyCode(ctx, input.NewEmail, models.PurposeChangeEmail, input.Code)
	if err != nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}
	//3. check if the code is for the same user
	if resp.Body.GetID() != codeValid.Body.UserId {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}
	email := strings.Split(codeValid.Body.Identifier, ":")
	//4. update the email
	updateResp, err := sql_db.DbUpdateOneById[T](aus.ProvServ.GormConn, ctx, userId, models.UserDto{Email: &email[1]}, nil)
	if err != nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}
	//5. delete all the users session
	_, err = sql_db.DbDeleteMany[models.Session](aus.ProvServ.GormConn, ctx, models.Session{UserId: userId}, nil)
	if err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}
	//TODO: black list all the sessions here
	// tasks.EnqueueAuditActivityLog(ctx, aus.ProvServ.QueueClient, aus.ProvServ.GormConn, tasks.AuditActivityLogPayload{
	// 	CompanyID:   "",
	// 	UserID:      userId,
	// 	Action:      "VERIFY_CHANGE_EMAIL",
	// 	EntityType:  "user",
	// 	EntityID:    userId,
	// 	Summary:     fmt.Sprintf("Email address updated to %s", email),
	// 	Changes:     fmt.Sprintf(`{"email": {"old": "[previous email]", "new": "%s"}}`, email),
	// 	LogAudit:    true,
	// 	LogActivity: true,
	// })
	return dtos.SuccessS(true, updateResp.RowsAffected), nil
}
