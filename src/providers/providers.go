package providers

import (
	"github.com/better-go-auth/goauth/src/config"
	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"gorm.io/gorm"
)

type IProviderS struct {
	EnvConf *config.SessionConfig
	//Infrastructure
	GormConn *gorm.DB

	KeyValServ db.KeyValServ//used for blacklisting session

	MiddleWare middleware.AuthMiddleware
}

func NewProvider(env *config.SessionConfig, conn *gorm.DB, keyValServ db.KeyValServ) *IProviderS {

	return &IProviderS{
		EnvConf: env,
		GormConn:   conn,
		KeyValServ: keyValServ,
	}
}
