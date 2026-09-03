package profile

import (
	"context"
	"strings"

	ICrypt "github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	sql_db "github.com/birukbelay/gocmn/src/generic"
	ICnst "github.com/birukbelay/gocmn/src/resp_const"

	"github.com/better-go-auth/goauth/src/app/account/account_interfaces"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers"
)

type Service[T models.IntUsr] struct {
	ProvServ *providers.IProviderS
	VSvc     account_interfaces.IVerificationService
	SesSvc   account_interfaces.ISessionService
}

func NewProfileServH[T models.IntUsr](genServ *providers.IProviderS, vSvc account_interfaces.IVerificationService, sesSvc account_interfaces.ISessionService) *Service[T] {
	return &Service[T]{
		ProvServ: genServ,
		VSvc:     vSvc,
		SesSvc:   sesSvc,
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

	err = aus.SesSvc.DeleteAllUserSessions(ctx, userId)
	if err != nil {
		return dtos.InternalErrMS[T]("Session Removing error"), err
	}
	return updateResp, nil
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

	return aus.VSvc.SendVerification(ctx, input.NewEmail, models.PurposeChangeEmail, &account_interfaces.VerOpt{UserId: resp.Body.GetID()})
}

// VerifyChangeEmail .change the users email
func (aus *Service[T]) VerifyChangeEmail(ctx context.Context, userId string, input models.VerifyEmailDto) (dtos.GResp[bool], error) {
	//1. Get the user
	resp, err := sql_db.DbGetOne[T](aus.ProvServ.GormConn, ctx, models.UserFilter{ID: userId}, nil)
	if err != nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}

	//2. Validate the code
	codeValid, err := aus.VSvc.VerifyCode(ctx, input.NewEmail, models.PurposeChangeEmail, input.Code)
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
	_, err = sql_db.DbDeleteMany[models.Session](aus.ProvServ.GormConn, ctx, models.Session{UserID: userId}, nil)
	if err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}

	return dtos.SuccessS(true, updateResp.RowsAffected), nil
}
