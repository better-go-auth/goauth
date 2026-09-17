package profile

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ICrypt "github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	sql_db "github.com/birukbelay/gocmn/src/generic"
	ICnst "github.com/birukbelay/gocmn/src/resp_const"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers"
)

type Service struct {
	ProvServ    *providers.IProviderS
	VSvc        serv_interfaces.IVerificationService
	SesSvc      serv_interfaces.ISessionService
	TxMgr       interfaces.ITransactionManager
	accountRepo repo_interfaces.IOAuthAccountRepo
}

func NewProfileServH(genServ *providers.IProviderS, vSvc serv_interfaces.IVerificationService, sesSvc serv_interfaces.ISessionService, accountRepo repo_interfaces.IOAuthAccountRepo) *Service {
	return &Service{
		ProvServ:    genServ,
		VSvc:        vSvc,
		SesSvc:      sesSvc,
		TxMgr:       gormutil.NewGormTxManager(genServ.GormConn),
		accountRepo: accountRepo,
	}
}

// ChangePassword updates user password using the Account model.
func (aus *Service) ChangePassword(ctx context.Context, userId, sessionId string, input models.PasswordUpdateDto) (dtos.GResp[models.User], error) {
	resp, err := sql_db.DbGetOne[models.User](aus.ProvServ.GormConn, ctx, models.UserFilter{ID: userId}, nil)
	if err != nil {
		return resp, err
	}

	account, err := aus.accountRepo.GetAccountByUserAndProvider(ctx, userId, models.ProvCredential)
	if err != nil || account == nil || account.Password == nil {
		return dtos.BadReqM[models.User](ICnst.PasswordDontMatch.Msg()), ICnst.PwdDontMatch
	}

	valid := ICrypt.BcryptPasswordsMatch(input.OldPassword, *account.Password)
	if !valid {
		return dtos.BadReqM[models.User](ICnst.PasswordDontMatch.Msg()), ICnst.PwdDontMatch
	}

	hash, err := ICrypt.BcryptCreateHash(input.NewPassword)
	if err != nil {
		return dtos.InternalErrMS[models.User]("Hashing Error"), err
	}

	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		_, err := aus.accountRepo.UpdateAccount(txCtx, account.ID, map[string]interface{}{"password": hash})
		if err != nil {
			return fmt.Errorf("profilesvc: update password: %w", err)
		}

		err = aus.SesSvc.DeleteAllUserSessions(txCtx, userId)
		if err != nil {
			return fmt.Errorf("profilesvc: remove sessions: %w", err)
		}
		return nil
	})
	if err != nil {
		return dtos.InternalErrMS[models.User](err.Error()), err
	}

	return resp, nil
}

// TODO: put the new email in the

// SendChangeEmail .params{userId: from token}
func (aus *Service) SendChangeEmail(ctx context.Context, userId string, input models.ChangeEmailReqDto) (dtos.GResp[bool], error) {
	// 1. get the user
	resp, err := sql_db.DbGetOne[models.User](aus.ProvServ.GormConn, ctx, models.UserFilter{ID: userId}, nil)
	if err != nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}

	// 2. check if password is correct from account model
	account, err := aus.accountRepo.GetAccountByUserAndProvider(ctx, userId, models.ProvCredential)
	if err != nil || account == nil || account.Password == nil {
		return dtos.BadReqM[bool](ICnst.InfoOrCode.Msg()), ICnst.InfoOrCodeErr
	}
	valid := ICrypt.BcryptPasswordsMatch(input.Password, *account.Password)
	if !valid {
		return dtos.BadReqM[bool](ICnst.InfoOrCode.Msg()), ICnst.InfoOrCodeErr
	}

	// 3. check if the new email already exists
	_, err = sql_db.DbGetOne[models.User](aus.ProvServ.GormConn, ctx, models.UserFilter{Email: input.NewEmail}, nil)
	if err == nil {
		return dtos.BadReqC[bool](ICnst.EmailExists), ICnst.EmailExistsErr
	}

	return aus.VSvc.SendVerification(ctx, input.NewEmail, models.PurposeChangeEmail, &serv_interfaces.VerOpt{UserId: resp.Body.GetID()})
}

// VerifyChangeEmail updates the user's email, syncs account_id on the Account model, and revokes sessions.
func (aus *Service) VerifyChangeEmail(ctx context.Context, userId string, input models.VerifyEmailDto) (dtos.GResp[bool], error) {
	// 1. Get the user
	resp, err := sql_db.DbGetOne[models.User](aus.ProvServ.GormConn, ctx, models.UserFilter{ID: userId}, nil)
	if err != nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}

	var rowsAffected int64
	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		// 2. Validate the code
		codeValid, err := aus.VSvc.VerifyCode(txCtx, input.NewEmail, models.PurposeChangeEmail, input.Code)
		if err != nil {
			return ICnst.InfoOrCodeErr
		}

		// 3. check if the code is for the same user
		if resp.Body.GetID() != codeValid.Body.UserId {
			return ICnst.InfoOrCodeErr
		}

		email := strings.Split(codeValid.Body.Identifier, ":")
		newEmail := email[1]

		// 4. update the email on User
		updateResp, err := sql_db.DbUpdateOneById[models.User](gormutil.GetDB(txCtx, aus.ProvServ.GormConn), txCtx, userId, models.UserDto{Email: &newEmail, EmailVerified: true}, nil)
		if err != nil {
			return err
		}
		rowsAffected = updateResp.RowsAffected

		// 5. update account account_id for ProvCredential if exists
		account, err := aus.accountRepo.GetAccountByUserAndProvider(txCtx, userId, models.ProvCredential)
		if err == nil && account != nil {
			_, err = aus.accountRepo.UpdateAccount(txCtx, account.ID, map[string]any{"account_id": newEmail})
			if err != nil {
				return fmt.Errorf("profilesvc: update account email: %w", err)
			}
		}

		// 6. clean up verification code
		_ = aus.VSvc.DeleteByIdentifier(txCtx, input.NewEmail, models.PurposeChangeEmail)

		// 7. delete all user sessions
		err = aus.SesSvc.DeleteAllUserSessions(txCtx, userId)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		if errors.Is(err, ICnst.InfoOrCodeErr) {
			return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
		}
		return dtos.InternalErrMS[bool](err.Error()), err
	}

	return dtos.SuccessCreated(true, rowsAffected), nil
}
