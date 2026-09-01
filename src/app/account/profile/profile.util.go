package profile

import (
	"context"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	ICrypt "github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/generic"
)

func (aus Service[T]) VerifyCode(ctx context.Context, userId string, code string) (bool, string) {
	codeModel, err := generic.DbGetOne[models.Verification](aus.ProvServ.GormConn, ctx, models.Verification{UserId: userId}, nil)
	if err != nil {
		return false, ""
	}
	if codeModel.Body.ExpiresAt.Before(time.Now()) {
		return false, ""
	}
	valid := ICrypt.BcryptPasswordsMatch(code, codeModel.Body.CodeHash)
	if !valid {
		return false, ""
	}
	return true, codeModel.Body.Email
}
