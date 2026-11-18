// Package humaopenapi mounts the open-api plugin endpoints on a Huma API.
package humaopenapi

import (
	"context"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/open-api/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpGenerateOpenAPISchema = "generateOpenAPISchema"
	OpOpenAPIReference      = "openAPIReference"
)

// ErrNotFound is better-auth's APIError("NOT_FOUND") of a disabled reference page.
var ErrNotFound = pluginkit.NewError(http.StatusNotFound, "NOT_FOUND", "Not Found")

// Handler adapts the open-api service to Huma operations.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the Huma handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

type schemaOutput struct {
	Body map[string]any
}

// GenerateSchema returns the OpenAPI document of the auth routes.
func (h *Handler) GenerateSchema(ctx context.Context, _ *struct{}) (*schemaOutput, error) {
	doc, err := h.Service.Generate(ctx)
	if err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	return &schemaOutput{Body: doc}, nil
}

type referenceOutput struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}

// Reference serves the Scalar API reference page.
func (h *Handler) Reference(ctx context.Context, _ *struct{}) (*referenceOutput, error) {
	// Step 1: a disabled page is a 404 like better-auth
	cfg := h.Service.Config()
	if cfg.DisableDefaultReference {
		return nil, ErrNotFound
	}
	// Step 2: the page embeds the current document
	doc, err := h.Service.Generate(ctx)
	if err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	page, err := services.ReferenceHTML(doc, cfg.Theme, cfg.Nonce)
	if err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	return &referenceOutput{ContentType: "text/html", Body: []byte(page)}, nil
}

// RegisterRoutes mounts GET /open-api/generate-schema and the reference page (hidden from the document).
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{services.Tag}
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGenerateOpenAPISchema, Method: http.MethodGet, Path: "/open-api/generate-schema",
		Summary: "Generate the OpenAPI document of the auth routes", Tags: tags, Access: pluginkit.Public,
	}, h.GenerateSchema)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpOpenAPIReference, Method: http.MethodGet, Path: h.Service.Config().Path,
		Summary: "Scalar API reference", Tags: tags, Access: pluginkit.Public, Hidden: true,
	}, h.Reference)
}
