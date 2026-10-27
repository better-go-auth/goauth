// Package middleware provides authorization middleware for the organization plugin,
// supporting both permission-based (resource:action) and operations-based (operationId) dynamic RBAC.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/plugins/org/config"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/danielgtaylor/huma/v2"
)

// AuthOptions configures authorization criteria for organization routes.
type AuthOptions struct {
	// Resource defines the resource being accessed (e.g. "project", "billing").
	Resource string
	// Action defines the required action (e.g. "read", "create", "delete").
	Action string
	// OperationID defines the operation identifier to verify in Ops array (e.g. "createProject").
	OperationID string
	// Method overrides the org plugin's default authorization method for this route.
	Method config.AuthMethod
}

// OrgAuthMiddleware evaluates dynamic organization role permissions and operations.
type OrgAuthMiddleware struct {
	service orgsvc.IOrgService
}

// New creates a new OrgAuthMiddleware backed by the provided IOrgService.
func New(service orgsvc.IOrgService) *OrgAuthMiddleware {
	return &OrgAuthMiddleware{service: service}
}

// ─── Huma Middlewares ────────────────────────────────────────────────────────

// Authorize returns a Huma middleware verifying authorization based on AuthOptions.
func (m *OrgAuthMiddleware) Authorize(opts AuthOptions) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// Step 1: Extract authenticated claims from request context
		claims, ok := claimsFromHumaCtx(ctx)
		if !ok || claims.UserID == "" {
			writeAuthError(ctx, autherr.ErrUnauthorized)
			return
		}

		// Step 2: Resolve Active Organization ID and member role
		orgID, role, authErr := m.resolveOrgAndRole(ctx.Context(), claims, ctx.Header("X-Organization-Id"))
		if authErr != nil {
			writeAuthError(ctx, authErr)
			return
		}

		// Step 3: Evaluate authorization via dynamic role service
		authorized, err := m.service.AuthorizeRole(ctx.Context(), orgID, role, orgsvc.AuthCheck{
			Resource:    opts.Resource,
			Action:      opts.Action,
			OperationID: opts.OperationID,
			Method:      opts.Method,
		})
		if err != nil || !authorized {
			writeAuthError(ctx, autherr.ErrForbidden)
			return
		}

		// Step 4: Authorization granted, proceed to next handler
		next(ctx)
	}
}

// RequirePermission returns a Huma middleware checking resource and action permissions (e.g. "project", "read").
func (m *OrgAuthMiddleware) RequirePermission(resource, action string) func(huma.Context, func(huma.Context)) {
	return m.Authorize(AuthOptions{
		Resource: resource,
		Action:   action,
		Method:   config.AuthMethodPermission,
	})
}

// RequireOperation returns a Huma middleware checking if the operation ID exists in the role's Ops array.
func (m *OrgAuthMiddleware) RequireOperation(operationID string) func(huma.Context, func(huma.Context)) {
	return m.Authorize(AuthOptions{
		OperationID: operationID,
		Method:      config.AuthMethodOperations,
	})
}

// ─── Standard net/http Middlewares ──────────────────────────────────────────

// HTTPAuthorize returns a standard net/http middleware verifying authorization based on AuthOptions.
func (m *OrgAuthMiddleware) HTTPAuthorize(opts AuthOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Step 1: Extract authenticated claims from request context
			claims, ok := claimsFromHTTPCtx(r.Context())
			if !ok || claims.UserID == "" {
				writeHTTPAuthError(w, autherr.ErrUnauthorized)
				return
			}

			// Step 2: Resolve Active Organization ID and member role
			orgID, role, authErr := m.resolveOrgAndRole(r.Context(), claims, r.Header.Get("X-Organization-Id"))
			if authErr != nil {
				writeHTTPAuthError(w, authErr)
				return
			}

			// Step 3: Evaluate authorization via dynamic role service
			authorized, err := m.service.AuthorizeRole(r.Context(), orgID, role, orgsvc.AuthCheck{
				Resource:    opts.Resource,
				Action:      opts.Action,
				OperationID: opts.OperationID,
				Method:      opts.Method,
			})
			if err != nil || !authorized {
				writeHTTPAuthError(w, autherr.ErrForbidden)
				return
			}

			// Step 4: Authorization granted, proceed to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// HTTPRequirePermission returns a standard net/http middleware checking resource and action permissions.
func (m *OrgAuthMiddleware) HTTPRequirePermission(resource, action string) func(http.Handler) http.Handler {
	return m.HTTPAuthorize(AuthOptions{
		Resource: resource,
		Action:   action,
		Method:   config.AuthMethodPermission,
	})
}

// HTTPRequireOperation returns a standard net/http middleware checking operation ID.
func (m *OrgAuthMiddleware) HTTPRequireOperation(operationID string) func(http.Handler) http.Handler {
	return m.HTTPAuthorize(AuthOptions{
		OperationID: operationID,
		Method:      config.AuthMethodOperations,
	})
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

func (m *OrgAuthMiddleware) resolveOrgAndRole(ctx context.Context, claims token.CustomClaims, orgHeader string) (string, string, *autherr.AuthError) {
	// Step 1: Resolve organization ID from token claims or header
	orgID := claims.ActiveOrgId
	if orgID == "" && orgHeader != "" {
		orgID = orgHeader
	}
	if orgID == "" {
		return "", "", autherr.ErrForbidden
	}

	// Step 2: Resolve role from token claims, falling back to database member lookup if necessary
	role := claims.ActiveOrgRole
	if role == "" {
		member, err := m.service.GetMember(ctx, orgID, claims.UserID)
		if err != nil || member == nil {
			return "", "", autherr.ErrForbidden
		}
		role = string(member.Role)
	}

	return orgID, role, nil
}

func claimsFromHumaCtx(ctx huma.Context) (token.CustomClaims, bool) {
	return claimsFromHTTPCtx(ctx.Context())
}

func claimsFromHTTPCtx(ctx context.Context) (token.CustomClaims, bool) {
	v := ctx.Value(consts.CtxClaims.Str())
	switch c := v.(type) {
	case token.CustomClaims:
		return c, true
	case *token.CustomClaims:
		if c != nil {
			return *c, true
		}
	}
	return token.CustomClaims{}, false
}

func writeAuthError(ctx huma.Context, err *autherr.AuthError) {
	if err == nil {
		err = autherr.ErrUnauthorized
	}
	ctx.SetStatus(err.StatusCode)
	ctx.SetHeader("Content-Type", "application/json")
	_ = json.NewEncoder(ctx.BodyWriter()).Encode(err)
}

func writeHTTPAuthError(w http.ResponseWriter, err *autherr.AuthError) {
	if err == nil {
		err = autherr.ErrUnauthorized
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	_ = json.NewEncoder(w).Encode(err)
}
