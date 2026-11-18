// Package humascim mounts the scim endpoints on a Huma API.
package humascim

import (
	"context"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	scimdtos "github.com/better-go-auth/goauth/src/plugins/scim/dtos"
	"github.com/better-go-auth/goauth/src/plugins/scim/services"
)

// Handler adapts the scim service to Huma.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

// sessionUser loads the session user as a models.User (hooks receive the full user).
func (h *Handler) sessionUser(ctx context.Context) (*models.User, error) {
	kit := h.Service.Kit()
	current := kit.Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	u, err := pluginkit.AcceptNotFound(kit.Repos.FindUserByID(ctx, current.User.ID))
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, autherr.ErrUnauthorized
	}
	return u, nil
}

// ─── management (session) ────────────────────────────────────────────────────

type generateTokenInput struct {
	Body scimdtos.SCIMGenerateTokenInput
}

type tokenOutput struct {
	Status int
	Body   scimdtos.SCIMTokenResponse
}

// GenerateToken is POST /scim/generate-token (201).
func (h *Handler) GenerateToken(ctx context.Context, in *generateTokenInput) (*tokenOutput, error) {
	user, err := h.sessionUser(ctx)
	if err != nil {
		return nil, err
	}
	token, err := h.Service.GenerateToken(ctx, user, in.Body.ProviderID, in.Body.OrganizationID)
	if err != nil {
		return nil, err
	}
	return &tokenOutput{Status: http.StatusCreated, Body: scimdtos.SCIMTokenResponse{SCIMToken: token}}, nil
}

type connectionsOutput struct {
	Body *scimdtos.SCIMProviderConnections
}

// ListConnections is GET /scim/list-provider-connections.
func (h *Handler) ListConnections(ctx context.Context, _ *struct{}) (*connectionsOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	res, err := h.Service.ListConnections(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	return &connectionsOutput{Body: res}, nil
}

type getConnectionInput struct {
	ProviderID string `query:"providerId" required:"true"`
}

type connectionOutput struct {
	Body *scimdtos.SCIMProviderConnection
}

// GetConnection is GET /scim/get-provider-connection.
func (h *Handler) GetConnection(ctx context.Context, in *getConnectionInput) (*connectionOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	res, err := h.Service.GetConnection(ctx, current.User.ID, in.ProviderID)
	if err != nil {
		return nil, err
	}
	return &connectionOutput{Body: res}, nil
}

type deleteConnectionInput struct {
	Body scimdtos.SCIMProviderIDInput
}

type successOutput struct {
	Body scimdtos.SCIMSuccessResponse
}

// DeleteConnection is POST /scim/delete-provider-connection.
func (h *Handler) DeleteConnection(ctx context.Context, in *deleteConnectionInput) (*successOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	if err := h.Service.DeleteConnection(ctx, current.User.ID, in.Body.ProviderID); err != nil {
		return nil, err
	}
	return &successOutput{Body: scimdtos.SCIMSuccessResponse{Success: true}}, nil
}

// ─── SCIM users (bearer token) ───────────────────────────────────────────────

type userBodyInput struct {
	Authorization string `header:"Authorization"`
	RawBody       []byte
}

type userPathInput struct {
	UserID        string `path:"userId"`
	Authorization string `header:"Authorization"`
}

type userPathBodyInput struct {
	UserID        string `path:"userId"`
	Authorization string `header:"Authorization"`
	RawBody       []byte
}

type listUsersInput struct {
	Filter        string `query:"filter"`
	Authorization string `header:"Authorization"`
}

type userOutput struct {
	Status   int
	Location string `header:"Location"`
	Body     *scimdtos.SCIMUserResource
}

type listOutput struct {
	Body *scimdtos.SCIMUserList
}

type noContentOutput struct {
	Status int
}

// CreateUser is POST /scim/v2/Users (201 + Location).
func (h *Handler) CreateUser(ctx context.Context, in *userBodyInput) (*userOutput, error) {
	// Step 1: the body is validated before the token (better-call validates before middlewares)
	body, err := services.ParseUserInput(in.RawBody)
	if err != nil {
		return nil, err
	}
	// Step 2: the SCIM token
	p, err := h.Service.Authenticate(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	res, err := h.Service.CreateUser(ctx, p, body)
	if err != nil {
		return nil, err
	}
	return &userOutput{Status: http.StatusCreated, Location: res.Meta.Location, Body: res}, nil
}

// ListUsers is GET /scim/v2/Users.
func (h *Handler) ListUsers(ctx context.Context, in *listUsersInput) (*listOutput, error) {
	p, err := h.Service.Authenticate(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	res, err := h.Service.ListUsers(ctx, p, in.Filter)
	if err != nil {
		return nil, err
	}
	return &listOutput{Body: res}, nil
}

// GetUser is GET /scim/v2/Users/{userId}.
func (h *Handler) GetUser(ctx context.Context, in *userPathInput) (*userOutput, error) {
	p, err := h.Service.Authenticate(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	res, err := h.Service.GetUser(ctx, p, in.UserID)
	if err != nil {
		return nil, err
	}
	return &userOutput{Status: http.StatusOK, Body: res}, nil
}

// UpdateUser is PUT /scim/v2/Users/{userId}.
func (h *Handler) UpdateUser(ctx context.Context, in *userPathBodyInput) (*userOutput, error) {
	body, err := services.ParseUserInput(in.RawBody)
	if err != nil {
		return nil, err
	}
	p, err := h.Service.Authenticate(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	res, err := h.Service.UpdateUser(ctx, p, in.UserID, body)
	if err != nil {
		return nil, err
	}
	return &userOutput{Status: http.StatusOK, Body: res}, nil
}

// PatchUser is PATCH /scim/v2/Users/{userId} (204).
func (h *Handler) PatchUser(ctx context.Context, in *userPathBodyInput) (*noContentOutput, error) {
	ops, err := services.ParsePatchInput(in.RawBody)
	if err != nil {
		return nil, err
	}
	p, err := h.Service.Authenticate(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if err := h.Service.PatchUser(ctx, p, in.UserID, ops); err != nil {
		return nil, err
	}
	return &noContentOutput{Status: http.StatusNoContent}, nil
}

// DeleteUser is DELETE /scim/v2/Users/{userId} (204).
func (h *Handler) DeleteUser(ctx context.Context, in *userPathInput) (*noContentOutput, error) {
	p, err := h.Service.Authenticate(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if err := h.Service.DeleteUser(ctx, p, in.UserID); err != nil {
		return nil, err
	}
	return &noContentOutput{Status: http.StatusNoContent}, nil
}

// ─── SCIM metadata (public) ──────────────────────────────────────────────────

type spConfigOutput struct {
	Body services.SCIMServiceProviderConfig
}

// ServiceProviderConfig is GET /scim/v2/ServiceProviderConfig.
func (h *Handler) ServiceProviderConfig(context.Context, *struct{}) (*spConfigOutput, error) {
	return &spConfigOutput{Body: services.ServiceProviderConfiguration()}, nil
}

type schemasOutput struct {
	Body services.SCIMListResponse[services.SCIMSchemaResource]
}

// Schemas is GET /scim/v2/Schemas.
func (h *Handler) Schemas(ctx context.Context, _ *struct{}) (*schemasOutput, error) {
	return &schemasOutput{Body: services.Schemas(h.Service.Kit().RequestBaseURL(ctx))}, nil
}

type schemaInput struct {
	SchemaID string `path:"schemaId"`
}

type schemaOutput struct {
	Body *services.SCIMSchemaResource
}

// Schema is GET /scim/v2/Schemas/{schemaId}.
func (h *Handler) Schema(ctx context.Context, in *schemaInput) (*schemaOutput, error) {
	s, err := services.Schema(h.Service.Kit().RequestBaseURL(ctx), in.SchemaID)
	if err != nil {
		return nil, err
	}
	return &schemaOutput{Body: s}, nil
}

type resourceTypesOutput struct {
	Body services.SCIMListResponse[services.SCIMResourceType]
}

// ResourceTypes is GET /scim/v2/ResourceTypes.
func (h *Handler) ResourceTypes(ctx context.Context, _ *struct{}) (*resourceTypesOutput, error) {
	return &resourceTypesOutput{Body: services.ResourceTypes(h.Service.Kit().RequestBaseURL(ctx))}, nil
}

type resourceTypeInput struct {
	ResourceTypeID string `path:"resourceTypeId"`
}

type resourceTypeOutput struct {
	Body *services.SCIMResourceType
}

// ResourceType is GET /scim/v2/ResourceTypes/{resourceTypeId}.
func (h *Handler) ResourceType(ctx context.Context, in *resourceTypeInput) (*resourceTypeOutput, error) {
	r, err := services.ResourceTypeByID(h.Service.Kit().RequestBaseURL(ctx), in.ResourceTypeID)
	if err != nil {
		return nil, err
	}
	return &resourceTypeOutput{Body: r}, nil
}
