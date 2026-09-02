package gormutil

import (
	"context"

	"gorm.io/gorm"
)

type ContextKey string

const TxKey ContextKey = "gorm_tx"

// GetDB retrieves the active GORM transaction DB from the context,
// or falls back to the default db with context.
func GetDB(ctx context.Context, fallback *gorm.DB) *gorm.DB {
	if tx, ok := ctx.Value(TxKey).(*gorm.DB); ok {
		return tx.WithContext(ctx)
	}
	return fallback.WithContext(ctx)
}
