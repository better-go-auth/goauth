package fiberadapter

import (
	"github.com/better-go-auth/goauth/adapters"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"
	fiber "github.com/gofiber/fiber/v2"
)

// New initializes a Huma API instance using a Fiber v2 application.
func New(app *fiber.App, opts ...adapters.Option) huma.API {
	// 1. Build the huma.Config from the provided options (docs, OpenAPI, title, renderer)
	cfg := adapters.BuildConfig(opts...)

	// 2. Wrap the Fiber app using humafiber adapter
	return humafiber.NewV2(app, cfg)
}

// NewWithGroup initializes a Huma API instance scoped to a Fiber v2 router group.
func NewWithGroup(app *fiber.App, g fiber.Router, opts ...adapters.Option) huma.API {
	// 1. Build the huma.Config from the provided options
	cfg := adapters.BuildConfig(opts...)

	// 2. Wrap the Fiber router group using humafiber adapter
	return humafiber.NewV2WithGroup(app, g, cfg)
}
