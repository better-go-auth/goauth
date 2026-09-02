package gormutil

import (
	"context"

	"github.com/better-go-auth/goauth/src/common/interfaces"

	"gorm.io/gorm"
)

// GormTxManager implements repoimpl.ITransactionManager for GORM.
type GormTxManager struct {
	db *gorm.DB
}

// NewGormTxManager creates a new GORM-backed ITransactionManager.
func NewGormTxManager(db *gorm.DB) interfaces.ITransactionManager {
	return &GormTxManager{db: db}
}

// Transaction executes a function in a database transaction.
// If a transaction is already active in ctx it is reused (nested-safe).
func (m *GormTxManager) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(TxKey).(*gorm.DB); ok {
		return fn(ctx)
	}
	return m.db.Transaction(func(tx *gorm.DB) error {
		txCtx := context.WithValue(ctx, TxKey, tx)
		return fn(txCtx)
	})
}
