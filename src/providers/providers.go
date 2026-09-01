package providers

import (
	"github.com/better-go-auth/goauth/src/app/account/interfaces"
	"github.com/better-go-auth/goauth/src/models/config"
	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/birukbelay/gocmn/src/provider/upload"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"gorm.io/gorm"

	"github.com/birukbelay/gocmn/src/provider/email"
)

type IProviderS struct {
	EnvConf *config.EnvConfig
	//Infrastructure
	GormConn *gorm.DB

	KeyValServ db.KeyValServ
	UploadServ upload.FileUploadWithPresigning
	//verification related
	VerificationCodeSender email.VerificationSender

	MiddleWare         middleware.AuthMiddleware
	VerificatinService interfaces.VerificationService
}

func NewProvider(
	env *config.EnvConfig,
	//db related
	conn *gorm.DB,
	keyValServ db.KeyValServ,
	//verification related
	verificationSender email.VerificationSender,
) *IProviderS {

	return &IProviderS{
		EnvConf: env,
		//verification related
		VerificationCodeSender: verificationSender,
		//db related
		GormConn:   conn,
		KeyValServ: keyValServ,
	}
}
