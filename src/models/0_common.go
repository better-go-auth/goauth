package models

import (
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

// func Ptr[T any](value T) *T {
// 	return &value
// }

type Base struct {
	ID        string     `gorm:"primarykey" json:"id,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func (m *Base) BeforeCreate(tx *gorm.DB) (err error) {
	if m.ID == "" {
		m.ID = ulid.Make().String()
	}
	return nil
}

func (b Base) GetID() string {
	return b.ID
}

type SDBase struct {
	ID        string         `gorm:"primarykey" json:"id,omitempty"`
	CreatedAt *time.Time     `json:"created_at,omitempty"`
	UpdatedAt *time.Time     `json:"updated_at,omitempty"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (m *SDBase) BeforeCreate(tx *gorm.DB) (err error) {
	if m.ID == "" {
		m.ID = ulid.Make().String()
	}
	return nil
}

func (b SDBase) GetID() string {
	return b.ID
}
