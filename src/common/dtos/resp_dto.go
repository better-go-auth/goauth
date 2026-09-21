package dtos

import (
	apperrors "github.com/better-go-auth/goauth/src/common/errors"
)

type PResp[T any] struct {
	Body         T                  `json:"body"`
	Status       int                `json:"status,omitempty"`
	RowsAffected int64              `json:"rows_affected"`
	Count        int64              `json:"count,omitempty"`
	HasMore      bool               `json:"has_more"`
	HasPrev      bool               `json:"has_prev"`
	Code         apperrors.RespCode `json:"code,omitempty"`
	Message      string             `json:"message,omitempty"`
	Error        string             `json:"error,omitempty"`
}

type GResp[T any] struct {
	Body         T     `json:"body"`
	Status       int   `json:"status,omitempty"`
	RowsAffected int64 `json:"rows_affected"`

	Code    apperrors.RespCode `json:"code,omitempty"`
	Message string             `json:"message,omitempty"`
	Error   string             `json:"error,omitempty"`

	Ok bool `json:"ok,omitempty"`
}

type PaginationInput struct {
	Limit int `default:"25" query:"_limit"`
	Page  int `default:"1"  query:"_page"`

	SortDir     string   `query:"_sort_dir" enum:"asc,desc" default:"desc"`
	AllowedSort []string `query:"-"`

	Select []string `query:"-"`
	SortBy string   `query:"-"`
}
