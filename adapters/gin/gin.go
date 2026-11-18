package ginadapter

import (
	"github.com/better-go-auth/goauth/adapters"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humagin"
	"github.com/gin-gonic/gin"
)

// New initializes a Huma API instance using a Gin engine.
func New(r *gin.Engine, opts ...adapters.Option) huma.API {
	// 1. Build the huma.Config from the provided options (docs, OpenAPI, title, renderer)
	cfg := adapters.BuildConfig(opts...)

	// 2. Wrap the Gin engine using humagin adapter
	return humagin.New(r, cfg)
}

// NewWithGroup initializes a Huma API instance scoped to a Gin router group.
func NewWithGroup(r *gin.Engine, g *gin.RouterGroup, opts ...adapters.Option) huma.API {
	// 1. Build the huma.Config from the provided options
	cfg := adapters.BuildConfig(opts...)

	// 2. Wrap the Gin router group using humagin adapter
	return humagin.NewWithGroup(r, g, cfg)
}
