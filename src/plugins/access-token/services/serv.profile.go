package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	interfaces1 "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	ICnst "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// ProfileService implements IAccessTokenProfileService.
type ProfileService struct {
	ProvServ    *providers.IProviderS
	VSvc        interfaces1.IVerificationService
	SesSvc      *SessionService
	TxMgr       interfaces.ITransactionManager
	UserRepo    repo_interfaces.IUserRepo
	AccountRepo repo_interfaces.IOAuthAccountRepo
	// Passwords hashes/verifies passwords; nil means legacy bcrypt.
	Passwords   *authcrypto.Passwords
}

var _ interfaces1.IAccessTokenProfileService = (*ProfileService)(nil)

// NewProfileServH creates a ProfileService with IProviderS (backward compatibility).
func NewProfileServH(genServ *providers.IProviderS, vSvc interfaces1.IVerificationService, sesSvc *SessionService, authRepos repo_interfaces.IAuthRepos) *ProfileService {
	var txMgr interfaces.ITransactionManager
	if genServ != nil {
		txMgr = genServ.TxManager
	}
	if txMgr == nil && genServ != nil && genServ.GormConn != nil {
		txMgr = gormutil.NewGormTxManager(genServ.GormConn)
	}

	return &ProfileService{
		ProvServ:    genServ,
		VSvc:        vSvc,
		SesSvc:      sesSvc,
		TxMgr:       txMgr,
		UserRepo:    authRepos,
		AccountRepo: authRepos,
	}
}

// NewProfileService creates a new ProfileService for the access-token plugin.
func NewProfileService(
	vSvc interfaces1.IVerificationService,
	sesSvc *SessionService,
	authRepos repo_interfaces.IAuthRepos,
	txMgr interfaces.ITransactionManager,
	passwords *authcrypto.Passwords,
) *ProfileService {
	return &ProfileService{
		VSvc:        vSvc,
		SesSvc:      sesSvc,
		TxMgr:       txMgr,
		UserRepo:    authRepos,
		AccountRepo: authRepos,
		Passwords:   passwords,
	}
}

// GetProfile retrieves a user's profile by ID.
func (aus *ProfileService) GetProfile(ctx context.Context, userId string) (*models.User, error) {
	if aus.UserRepo != nil {
		return aus.UserRepo.FindUserByID(ctx, userId)
	}
	return nil, errors.New("profilesvc: user repository not configured")
}

// UpdateProfile updates user profile fields.
func (aus *ProfileService) UpdateProfile(ctx context.Context, userId string, update models.ProfileUpdateDto) (*models.User, error) {
	if aus.UserRepo == nil {
		return nil, errors.New("profilesvc: user repository not configured")
	}
	data := make(map[string]interface{})
	if update.FirstName != "" {
		data["FirstName"] = update.FirstName
	}
	if update.LastName != "" {
		data["LastName"] = update.LastName
	}
	if update.Avatar != "" {
		data["Image"] = update.Avatar
	}
	return aus.UserRepo.UpdateUser(ctx, userId, data)
}

// ChangePassword updates user password using the Account model.
func (aus *ProfileService) ChangePassword(ctx context.Context, userId, sessionId string, input models.PasswordUpdateDto) (dtos.GResp[models.User], error) {
	user, err := aus.GetProfile(ctx, userId)
	if err != nil || user == nil {
		return dtos.BadReqM[models.User]("user not found"), err
	}

	account, err := aus.AccountRepo.FindAccountByUserAndProvider(ctx, userId, models.ProvCredential)
	if err != nil || account == nil || account.Password == nil {
		return dtos.BadReqM[models.User](ICnst.PasswordDontMatch.Msg()), ICnst.PwdDontMatch
	}

	valid, _, _ := aus.Passwords.Verify(*account.Password, input.OldPassword)
	if !valid {
		return dtos.BadReqM[models.User](ICnst.PasswordDontMatch.Msg()), ICnst.PwdDontMatch
	}

	hash, err := aus.Passwords.Hash(input.NewPassword)
	if err != nil {
		return dtos.InternalErrMS[models.User]("Hashing Error"), err
	}

	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		_, err := aus.AccountRepo.UpdateAccount(txCtx, account.ID, map[string]interface{}{"Password": hash})
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

// Note: SendChangeEmail and VerifyChangeEmail are superseded by the email-otp plugin.
// func (aus *ProfileService) SendChangeEmail(ctx context.Context, userId string, input models.ChangeEmailReqDto) (dtos.GResp[bool], error) {
// 	if aus.UserRepo == nil {
// 		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
// 	}
// 	// 1. get the user
// 	user, err := aus.GetProfile(ctx, userId)
// 	if err != nil || user == nil {
// 		return dtos.BadReqC[bool](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
// 	}
//
// 	// 2. check if password is correct from account model
// 	account, err := aus.AccountRepo.FindAccountByUserAndProvider(ctx, userId, models.ProvCredential)
// 	if err != nil || account == nil || account.Password == nil {
// 		return dtos.BadReqM[bool](ICnst.InfoOrCode.Msg()), ICnst.InfoOrCodeErr
// 	}
// 	valid, _, _ := aus.Passwords.Verify(*account.Password, input.Password)
// 	if !valid {
// 		return dtos.BadReqM[bool](ICnst.InfoOrCode.Msg()), ICnst.InfoOrCodeErr
// 	}
//
// 	// 3. check if the new email already exists
// 	existing, err := aus.UserRepo.FindUserByEmail(ctx, input.NewEmail)
// 	if err == nil && existing != nil {
// 		return dtos.BadReqC[bool](ICnst.EmailExists), ICnst.EmailExistsErr
// 	}
//
// 	return aus.VSvc.SendVerification(ctx, input.NewEmail, models.PurposeChangeEmail, &interfaces1.VerOpt{UserId: user.ID})
// }
//
// func (aus *ProfileService) VerifyChangeEmail(ctx context.Context, userId string, sessionId string, input models.VerifyEmailDto) (dtos.GResp[models.User], error) {
// 	// 1. Get the user
// 	user, err := aus.GetProfile(ctx, userId)
// 	if err != nil || user == nil {
// 		return dtos.BadReqC[models.User](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
// 	}
//
// 	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
// 		// 2. Validate the code
// 		codeValid, err := aus.VSvc.VerifyCode(txCtx, input.NewEmail, models.PurposeChangeEmail, input.Code)
// 		if err != nil {
// 			return ICnst.InfoOrCodeErr
// 		}
//
// 		// 3. check if the code is for the same user
// 		if codeValid.Body.UserID != "" && user.ID != codeValid.Body.UserID {
// 			return ICnst.InfoOrCodeErr
// 		}
//
// 		emailParts := strings.Split(codeValid.Body.Identifier, ":")
// 		newEmail := input.NewEmail
// 		if len(emailParts) > 1 {
// 			newEmail = emailParts[1]
// 		}
// 		newEmail = strings.ToLower(newEmail)
//
// 		// 4. update the email on User
// 		updated, err := aus.UserRepo.UpdateUser(txCtx, userId, map[string]any{
// 			"Email":         newEmail,
// 			"EmailVerified": true,
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		user = updated
//
// 		// 5. update account account_id for ProvCredential if exists
// 		account, err := aus.AccountRepo.FindAccountByUserAndProvider(txCtx, userId, models.ProvCredential)
// 		if err == nil && account != nil {
// 			_, err = aus.AccountRepo.UpdateAccount(txCtx, account.ID, map[string]any{"AccountID": newEmail})
// 			if err != nil {
// 				return fmt.Errorf("profilesvc: update account email: %w", err)
// 			}
// 		}
//
// 		// 6. clean up verification code
// 		_ = aus.VSvc.DeleteByIdentifier(txCtx, input.NewEmail, models.PurposeChangeEmail)
//
// 		// 7. delete all user sessions
// 		err = aus.SesSvc.DeleteAllUserSessions(txCtx, userId)
// 		if err != nil {
// 			return err
// 		}
//
// 		return nil
// 	})
// 	if err != nil {
// 		if errors.Is(err, ICnst.InfoOrCodeErr) {
// 			return dtos.BadReqC[models.User](ICnst.InfoOrCode), ICnst.InfoOrCodeErr
// 		}
// 		return dtos.InternalErrMS[models.User](err.Error()), err
// 	}
//
// 	return dtos.SuccessCreated(*user, 1), nil
// }
