package providers

import (
	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"gorm.io/gorm"
)

type IProviderS struct {

	//Infrastructure
	GormConn *gorm.DB

	SecondaryStorage db.KeyValServ //used for blacklisting session

	MiddleWare *middleware.AuthMiddleware
}

func NewProvider(conn *gorm.DB, keyValServ db.KeyValServ, mdlware *middleware.AuthMiddleware) *IProviderS {

	return &IProviderS{
		GormConn:         conn,
		SecondaryStorage: keyValServ,
		MiddleWare:       mdlware,
	}
}
