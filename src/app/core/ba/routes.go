// Package ba registers better-auth compatible endpoints (compat mode).
package ba

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"slices"
	"strings"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/danielgtaylor/huma/v2"
)

// Deps are the shared services compat endpoints use.
type Deps struct {
	Conf     config.AuthConfig
	Sessions *sessionsvc.Manager
	Cookies  *cookies.Manager
	Resolver *humaadapter.Resolver
}

// RegisterRoutes mounts the compat endpoints implemented so far under Conf.BasePath.
func RegisterRoutes(api huma.API, d Deps) {
	h := &handler{Deps: d}
	reg := func(op huma.Operation, register func(huma.Operation)) {
		if slices.Contains(d.Conf.DisabledPaths, op.Path) {
			return
		}
		op.Path = strings.TrimSuffix(d.Conf.BasePath, "/") + op.Path
		op.Tags = []string{"better-auth"}
		op.Metadata = map[string]any{types.RawBodyMetaKey: true}
		register(op)
	}

	reg(huma.Operation{OperationID: "ok", Method: http.MethodGet, Path: "/ok", Summary: "Health check"},
		func(op huma.Operation) { huma.Register(api, op, h.ok) })
	reg(huma.Operation{OperationID: "error", Method: http.MethodGet, Path: "/error", Summary: "Error page"},
		func(op huma.Operation) { huma.Register(api, op, h.errorPage) })
	reg(huma.Operation{OperationID: "getSession", Method: http.MethodGet, Path: "/get-session", Summary: "Get the current session"},
		func(op huma.Operation) { huma.Register(api, op, h.getSession) })
	reg(huma.Operation{OperationID: "refreshSession", Method: http.MethodPost, Path: "/get-session", Summary: "Refresh the current session (deferSessionRefresh)"},
		func(op huma.Operation) { huma.Register(api, op, h.postSession) })
}

type handler struct {
	Deps
}

type okOutput struct {
	Body struct {
		OK bool `json:"ok"`
	}
}

func (h *handler) ok(context.Context, *struct{}) (*okOutput, error) {
	out := &okOutput{}
	out.Body.OK = true
	return out, nil
}

type errorInput struct {
	Error string `query:"error"`
}

type errorOutput struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}

func (h *handler) errorPage(_ context.Context, in *errorInput) (*errorOutput, error) {
	code := in.Error
	if code == "" {
		code = "UNKNOWN"
	}
	page := fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Error</title></head>`+
		`<body><h1>Something went wrong</h1><p>Error code: <code>%s</code></p></body></html>`, html.EscapeString(code))
	return &errorOutput{ContentType: "text/html; charset=utf-8", Body: []byte(page)}, nil
}
