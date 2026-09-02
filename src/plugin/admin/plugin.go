package admin

import (
	"github.com/birukbelay/gocmn/src/provider/db"
	"gorm.io/gorm"
)

type AdminOptions struct {
	GormConn   *gorm.DB
	KeyValServ db.KeyValServ
}
