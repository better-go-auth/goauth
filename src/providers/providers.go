package providers

import (
	"github.com/better-go-auth/goauth/src/common/interfaces"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/birukbelay/gocmn/src/server/middleware"
	"gorm.io/gorm"
)

type IProviderS struct {
	// Infrastructure
	GormConn *gorm.DB

	SecondaryStorage sec_storage.SecondaryStorage // used for blacklisting session

	MiddleWare *middleware.AuthMiddleware
	TxManager  interfaces.ITransactionManager
}

func NewProvider(conn *gorm.DB, secStore sec_storage.SecondaryStorage, mdlware *middleware.AuthMiddleware, txMgr interfaces.ITransactionManager) *IProviderS {
	return &IProviderS{
		GormConn:         conn,
		SecondaryStorage: secStore,
		MiddleWare:       mdlware,
		TxManager:        txMgr,
	}
}
