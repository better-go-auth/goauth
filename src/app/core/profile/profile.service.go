package profile

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/common/dtos"
	ICnst "github.com/better-go-auth/goauth/src/common/errors"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/better-go-auth/goauth/src/providers/hasher"
)

type Service struct {
	ProvServ    *providers.IProviderS
	VSvc        serv_interfaces.IVerificationService
	SesSvc      serv_interfaces.ISessionService
	TxMgr       interfaces.ITransactionManager
	userRepo    repo_interfaces.IUserRepo
	accountRepo repo_interfaces.IOAuthAccountRepo
}

func NewProfileServH(genServ *providers.IProviderS, vSvc serv_interfaces.IVerificationService, sesSvc serv_interfaces.ISessionService, authRepos repo_interfaces.IAuthRepos) *Service {
	var txMgr interfaces.ITransactionManager
	if genServ != nil {
		txMgr = genServ.TxManager
	}
	if txMgr == nil && genServ != nil && genServ.GormConn != nil {
		txMgr = gormutil.NewGormTxManager(genServ.GormConn)
	}

	return &Service{
		ProvServ:    genServ,
		VSvc:        vSvc,
		SesSvc:      sesSvc,
		TxMgr:       txMgr,
		userRepo:    authRepos,
		accountRepo: authRepos,
	}
}

// GetProfile retrieves a user's profile by ID.
func (aus *Service) GetProfile(ctx context.Context, userId string) (*models.User, error) {
	if aus.userRepo != nil {
		return aus.userRepo.GetUserByID(ctx, userId)
	}
	return nil, errors.New("profilesvc: user repository not configured")
}

// UpdateProfile updates user profile fields.
func (aus *Service) UpdateProfile(ctx context.Context, userId string, update models.ProfileUpdateDto) (*models.User, error) {
	if aus.userRepo == nil {
		return nil, errors.New("profilesvc: user repository not configured")
	}
	data := make(map[string]interface{})
	if update.FirstName != "" {
		data["first_name"] = update.FirstName
	}
	if update.LastName != "" {
		data["last_name"] = update.LastName
	}
	if update.Avatar != "" {
		data["image"] = update.Avatar
	}
	return aus.userRepo.UpdateUser(ctx, userId, data)
}

// ChangePassword updates user password using the Account model.
func (aus *Service) ChangePassword(ctx context.Context, userId, sessionId string, input models.PasswordUpdateDto) (dtos.GResp[models.User], error) {
	user, err := aus.GetProfile(ctx, userId)
	if err != nil || user == nil {
		return dtos.BadReqM[models.User]("user not found"), err
	}

	account, err := aus.accountRepo.GetAccountByUserAndProvider(ctx, userId, models.ProvCredential)
	if err != nil || account == nil || account.Password == nil {
		return dtos.BadReqM[models.User](ICnst.PasswordDontMatch.Msg()), ICnst.PwdDontMatch
	}

	valid := hasher.BcryptPasswordsMatch(input.OldPassword, *account.Password)
	if !valid {
		return dtos.BadReqM[models.User](ICnst.PasswordDontMatch.Msg()), ICnst.PwdDontMatch
	}

	hash, err := hasher.BcryptCreateHash(input.NewPassword)
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

	return dtos.SuccessCreated(*user, 1), nil
}

// TODO: put the new email in the

// SendChangeEmail .params{userId: from token}
func (aus *Service) SendChangeEmail(ctx context.Context, userId string, input models.ChangeEmailReqDto) (dtos.GResp[bool], error) {
	if aus.userRepo == nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}
	// 1. get the user
	user, err := aus.GetProfile(ctx, userId)
	if err != nil || user == nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}

	// 2. check if password is correct from account model
	account, err := aus.accountRepo.GetAccountByUserAndProvider(ctx, userId, models.ProvCredential)
	if err != nil || account == nil || account.Password == nil {
		return dtos.BadReqM[bool](ICnst.InfoOrCode.Msg()), ICnst.InfoOrCodeErr
	}
	valid := hasher.BcryptPasswordsMatch(input.Password, *account.Password)
	if !valid {
		return dtos.BadReqM[bool](ICnst.InfoOrCode.Msg()), ICnst.InfoOrCodeErr
	}

	// 3. check if the new email already exists

	existing, err := aus.userRepo.GetUserByEmail(ctx, input.NewEmail)
	if err == nil && existing != nil {
		return dtos.BadReqC[bool](ICnst.EmailExists), ICnst.EmailExistsErr
	}

	return aus.VSvc.SendVerification(ctx, input.NewEmail, models.PurposeChangeEmail, &serv_interfaces.VerOpt{UserId: user.ID})
}

// VerifyChangeEmail updates the user's email, syncs account_id on the Account model, and revokes sessions.
func (aus *Service) VerifyChangeEmail(ctx context.Context, userId string, input models.VerifyEmailDto) (dtos.GResp[bool], error) {
	// 1. Get the user
	user, err := aus.GetProfile(ctx, userId)
	if err != nil || user == nil {
		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
	}

	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		// 2. Validate the code
		codeValid, err := aus.VSvc.VerifyCode(txCtx, input.NewEmail, models.PurposeChangeEmail, input.Code)
		if err != nil {
			return ICnst.InfoOrCodeErr
		}

		// 3. check if the code is for the same user
		if user.ID != codeValid.Body.UserId {
			return ICnst.InfoOrCodeErr
		}

		emailParts := strings.Split(codeValid.Body.Identifier, ":")
		newEmail := input.NewEmail
		if len(emailParts) > 1 {
			newEmail = emailParts[1]
		}
		newEmail = strings.ToLower(newEmail)

		// 4. update the email on User
		_, err = aus.userRepo.UpdateUser(txCtx, userId, map[string]interface{}{
			"email":          newEmail,
			"email_verified": true,
		})
		if err != nil {
			return err
		}

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

	return dtos.SuccessCreated(true, 1), nil
}
