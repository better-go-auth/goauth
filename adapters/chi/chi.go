package chiadapter

import (
	"github.com/better-go-auth/goauth/adapters"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

// New initializes a Huma API instance using a Chi v5 router.
func New(r chi.Router, opts ...adapters.Option) huma.API {
	// 1. Build the huma.Config from the provided options (docs, OpenAPI, title, renderer)
	cfg := adapters.BuildConfig(opts...)

	// 2. Wrap the Chi router using humachi adapter
	return humachi.New(r, cfg)
}
