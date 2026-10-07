package humaadapter

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"slices"
	"strings"

	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/better-go-auth/goauth/src/providers/origin"
	"github.com/danielgtaylor/huma/v2"
)

// Deps are what the better-auth endpoints need.
type Deps struct {
	Conf     config.AuthConfig
	Auth     *authsvc.Service
	Sessions *sessionsvc.Manager
	Cookies  *cookies.Manager
	Resolver *Resolver
	Origins  *origin.Checker
}

type handler struct {
	Deps
}

// access selects the middlewares an endpoint runs behind.
type access int

const (
	public      access = iota // anyone; mutating requests still get the origin check
	form                      // sign-in/sign-up: origin check plus Sec-Fetch CSRF check
	withSession               // session optional (attached to ctx when present)
	session                   // session required (401 otherwise)
)

// RegisterRoutes mounts better-auth's core endpoints under Conf.BasePath.
func RegisterRoutes(api huma.API, d Deps) {
	h := &handler{Deps: d}
	reg := func(op huma.Operation, a access, register func(huma.Operation)) {
		if slices.Contains(d.Conf.DisabledPaths, op.Path) {
			return
		}
		op.Path = strings.TrimSuffix(d.Conf.BasePath, "/") + op.Path
		op.Tags = []string{"better-auth"}
		op.Metadata = map[string]any{types.RawBodyMetaKey: true}
		op.Middlewares = append(op.Middlewares, h.requestContext(), h.originCheck(a == form))
		switch a {
		case withSession:
			op.Middlewares = append(op.Middlewares, d.Resolver.Optional())
		case session:
			op.Middlewares = append(op.Middlewares, d.Resolver.Require())
		}
		register(op)
	}
	get := func(id, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodGet, Path: path, Summary: summary}
	}
	post := func(id, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodPost, Path: path, Summary: summary}
	}

	reg(get("ok", "/ok", "Health check"), public, func(op huma.Operation) { huma.Register(api, op, h.ok) })
	reg(get("error", "/error", "Error page"), public, func(op huma.Operation) { huma.Register(api, op, h.errorPage) })

	reg(get("getSession", "/get-session", "Get the current session"), public, func(op huma.Operation) { huma.Register(api, op, h.getSession) })
	reg(post("refreshSession", "/get-session", "Refresh the current session (deferSessionRefresh)"), public, func(op huma.Operation) { huma.Register(api, op, h.postSession) })
	reg(get("listSessions", "/list-sessions", "List the user's sessions"), session, func(op huma.Operation) { huma.Register(api, op, h.listSessions) })
	reg(post("revokeSession", "/revoke-session", "Revoke one session"), session, func(op huma.Operation) { huma.Register(api, op, h.revokeSession) })
	reg(post("revokeSessions", "/revoke-sessions", "Revoke all sessions"), session, func(op huma.Operation) { huma.Register(api, op, h.revokeSessions) })
	reg(post("revokeOtherSessions", "/revoke-other-sessions", "Revoke all other sessions"), session, func(op huma.Operation) { huma.Register(api, op, h.revokeOtherSessions) })
	reg(post("updateSession", "/update-session", "Update session fields"), session, func(op huma.Operation) { huma.Register(api, op, h.updateSession) })

	reg(post("signUpWithEmailAndPassword", "/sign-up/email", "Sign up with email and password"), form, func(op huma.Operation) { huma.Register(api, op, h.signUpEmail) })
	reg(post("signInEmail", "/sign-in/email", "Sign in with email and password"), form, func(op huma.Operation) { huma.Register(api, op, h.signInEmail) })
	reg(post("signOut", "/sign-out", "Sign out"), public, func(op huma.Operation) { huma.Register(api, op, h.signOut) })
	reg(post("verifyPassword", "/verify-password", "Check the current user's password"), session, func(op huma.Operation) { huma.Register(api, op, h.verifyPassword) })

	reg(post("sendVerificationEmail", "/send-verification-email", "Send a verification email"), withSession, func(op huma.Operation) { huma.Register(api, op, h.sendVerificationEmail) })
	reg(get("verifyEmail", "/verify-email", "Verify an email address"), withSession, func(op huma.Operation) { huma.Register(api, op, h.verifyEmail) })
	reg(post("changeEmail", "/change-email", "Change the user's email"), session, func(op huma.Operation) { huma.Register(api, op, h.changeEmail) })

	reg(post("requestPasswordReset", "/request-password-reset", "Send a password reset link"), public, func(op huma.Operation) { huma.Register(api, op, h.requestPasswordReset) })
	reg(get("resetPasswordCallback", "/reset-password/{token}", "Validate a reset link and redirect"), public, func(op huma.Operation) { huma.Register(api, op, h.resetPasswordCallback) })
	reg(post("resetPassword", "/reset-password", "Reset the password with a token"), public, func(op huma.Operation) { huma.Register(api, op, h.resetPassword) })
	reg(post("changePassword", "/change-password", "Change the user's password"), session, func(op huma.Operation) { huma.Register(api, op, h.changePassword) })

	reg(post("updateUser", "/update-user", "Update the user"), session, func(op huma.Operation) { huma.Register(api, op, h.updateUser) })
	reg(post("deleteUser", "/delete-user", "Delete the user"), session, func(op huma.Operation) { huma.Register(api, op, h.deleteUser) })
	reg(get("deleteUserCallback", "/delete-user/callback", "Confirm account deletion"), withSession, func(op huma.Operation) { huma.Register(api, op, h.deleteUserCallback) })
	reg(get("listUserAccounts", "/list-accounts", "List the user's accounts"), session, func(op huma.Operation) { huma.Register(api, op, h.listAccounts) })
	reg(post("unlinkAccount", "/unlink-account", "Unlink an account"), session, func(op huma.Operation) { huma.Register(api, op, h.unlinkAccount) })
}

type statusBody struct {
	Status bool `json:"status"`
}

type statusOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      statusBody
}

func statusOK() *statusOutput { return &statusOutput{Body: statusBody{Status: true}} }

// current returns the session a Resolver middleware attached.
func current(ctx context.Context) *dtos.SessionWithUser {
	sw, _ := FromContext(ctx)
	return sw
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
