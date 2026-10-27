package gormutil

import (
	"gorm.io/gorm"
)

// IDEnsurable is an interface for domain models that can auto-assign an ID.
type IDEnsurable interface {
	EnsureID()
}

// Preparable is an interface for domain models that normalize/prepare data before save.
type Preparable interface {
	PrepareSave()
}

// UTCEnsurable is an interface for domain models that normalize timestamps to UTC.
type UTCEnsurable interface {
	EnsureUTC()
}

// RegisterCallbacks attaches pure Go domain model hooks to GORM's Create pipeline
// so raw GORM operations automatically initialize IDs and normalize timestamps
// without leaking GORM types into domain models.
func RegisterCallbacks(db *gorm.DB) {
	_ = db.Callback().Create().Before("gorm:create").Register("goauth:lifecycle", func(d *gorm.DB) {
		if d.Statement == nil || d.Statement.Dest == nil {
			return
		}
		if ensurer, ok := d.Statement.Dest.(IDEnsurable); ok {
			ensurer.EnsureID()
		}
		if prep, ok := d.Statement.Dest.(Preparable); ok {
			prep.PrepareSave()
		}
		if utc, ok := d.Statement.Dest.(UTCEnsurable); ok {
			utc.EnsureUTC()
		}
	})
}
