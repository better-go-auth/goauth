package providers

import (
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"gorm.io/gorm"
)

type IProviderS struct {

	//Infrastructure
	GormConn *gorm.DB

	SecondaryStorage db.KeyValServ //used for blacklisting session

	MiddleWare *middleware.AuthMiddleware
	TxManager  interfaces.ITransactionManager
}

func NewProvider(conn *gorm.DB, keyValServ db.KeyValServ, mdlware *middleware.AuthMiddleware, txMgr interfaces.ITransactionManager) *IProviderS {

	return &IProviderS{
		GormConn:         conn,
		SecondaryStorage: keyValServ,
		MiddleWare:       mdlware,
		TxManager:        txMgr,
	}
}
