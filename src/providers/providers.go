package providers

import (
	"github.com/better-go-auth/goauth/src/models/config"
	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/birukbelay/gocmn/src/provider/db/redis"
	"github.com/birukbelay/gocmn/src/provider/upload"
	"github.com/birukbelay/gocmn/src/server/middleware"

	// "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/birukbelay/gocmn/src/provider/email"
)

type IProviderS struct {
	EnvConf *config.EnvConfig
	//Infrastructure
	GormConn   *gorm.DB
	RedisServ  *redis.RedisService
	KeyValServ db.KeyValServ
	UploadServ upload.FileUploadWithPresigning
	//Email related
	VerificationCodeSender email.VerificationSender
	EmailSender            email.SingleEmailSender
	MiddleWare             middleware.AuthMiddleware
}

func NewProvider(
	env *config.EnvConfig,
	//db related
	conn *gorm.DB, redis *redis.RedisService,
	keyValServ db.KeyValServ,
	//email related
	emailSender email.SingleEmailSender, verificationSender email.VerificationSender,
	//upload related
) *IProviderS {

	return &IProviderS{
		EnvConf: env,
		//email related
		EmailSender:            emailSender,
		VerificationCodeSender: verificationSender,
		//db related
		GormConn:   conn,
		KeyValServ: keyValServ,
		RedisServ:  redis,
		//file related

	}
}
