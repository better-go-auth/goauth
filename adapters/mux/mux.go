package muxadapter

import (
	"github.com/better-go-auth/goauth/adapters"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

// New initializes a Huma API instance using the standard Go net/http ServeMux.
func New(mux humago.Mux, opts ...adapters.Option) huma.API {
	// 1. Build the huma.Config from the provided options (docs, OpenAPI, title, renderer)
	cfg := adapters.BuildConfig(opts...)

	// 2. Wrap the net/http ServeMux using humago adapter
	return humago.New(mux, cfg)
}

// NewWithPrefix initializes a Huma API instance on a ServeMux with a path prefix.
func NewWithPrefix(mux humago.Mux, prefix string, opts ...adapters.Option) huma.API {
	// 1. Build the huma.Config from the provided options
	cfg := adapters.BuildConfig(opts...)

	// 2. Wrap the net/http ServeMux with prefix using humago adapter
	return humago.NewWithPrefix(mux, prefix, cfg)
}
