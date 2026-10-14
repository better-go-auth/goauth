package humaadapter

import (
	"context"
	"net/http"

	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

type getSessionInput struct {
	DisableCookieCache bool   `query:"disableCookieCache" doc:"Bypass the cookie cache (no-op until the cookie cache is implemented)"`
	DisableRefresh     bool   `query:"disableRefresh" doc:"Do not extend the session expiry"`
	Cookie             string `header:"Cookie"`
	Authorization      string `header:"Authorization"`
}

type getSessionBody struct {
	dtos.SessionWithUser
	NeedsRefresh *bool `json:"needsRefresh,omitempty"`
}

type getSessionOutput struct {
	CacheControl string        `header:"Cache-Control"`
	Pragma       string        `header:"Pragma"`
	SetCookie    []http.Cookie `header:"Set-Cookie"`
	// nil is written as JSON null, which is what better-auth returns without a session
	Body *getSessionBody
}

func (h *handler) GetSession(ctx context.Context, in *getSessionInput) (*getSessionOutput, error) {
	return h.session(ctx, in, h.Conf.Session.DeferSessionRefresh)
}

func (h *handler) PostSession(ctx context.Context, in *getSessionInput) (*getSessionOutput, error) {
	if !h.Conf.Session.DeferSessionRefresh {
		return nil, autherr.ErrMethodNotAllowedDeferSessionRequired
	}
	return h.session(ctx, in, false)
}

// session mirrors better-auth's getSession endpoint; when deferRefresh is set it reports needsRefresh instead of writing.
func (h *handler) session(ctx context.Context, in *getSessionInput, deferRefresh bool) (*getSessionOutput, error) {
	out := &getSessionOutput{CacheControl: "no-store", Pragma: "no-cache"}
	if sw, ok := FromContext(ctx); ok && sw != nil {
		out.Body = &getSessionBody{SessionWithUser: *sw}
		return out, nil
	}
	tok, ok := h.Cookies.SessionToken(in.Cookie)
	if !ok {
		if btok, bok := FromBearerContext(ctx); bok {
			tok, ok = btok, true
		}
	}
	if !ok {
		return out, nil
	}
	dontRemember := h.Cookies.DontRemember(in.Cookie)
	res, err := h.Auth.GetSession(ctx, tok, svcint.GetSessionOptions{
		DisableRefresh: in.DisableRefresh,
		DeferRefresh:   deferRefresh,
		DontRemember:   dontRemember,
	})
	if err != nil {
		return nil, err
	}
	if res.Session == nil {
		out.SetCookie = h.Cookies.ExpireSessionCookies()
		return out, nil
	}
	body := &getSessionBody{SessionWithUser: *res.Session}
	if deferRefresh {
		body.NeedsRefresh = &res.NeedsRefresh
	}
	if res.Refreshed {
		out.SetCookie = h.Cookies.SessionCookies(tok, false)
	}
	out.Body = body
	return out, nil
}

type listSessionsOutput struct {
	Body []dtos.SessionData
}

func (h *handler) ListSessions(ctx context.Context, _ *struct{}) (*listSessionsOutput, error) {
	list, err := h.Auth.ListSessions(ctx, current(ctx))
	if err != nil {
		return nil, err
	}
	return &listSessionsOutput{Body: list}, nil
}

type revokeSessionInput struct {
	Body struct {
		Token string `json:"token" doc:"The token of the session to revoke"`
	}
}

func (h *handler) RevokeSession(ctx context.Context, in *revokeSessionInput) (*statusOutput, error) {
	if err := h.Auth.RevokeSession(ctx, current(ctx), in.Body.Token); err != nil {
		return nil, err
	}
	return statusOK(), nil
}

func (h *handler) RevokeSessions(ctx context.Context, _ *struct{}) (*statusOutput, error) {
	if err := h.Auth.RevokeSessions(ctx, current(ctx)); err != nil {
		return nil, err
	}
	return statusOK(), nil
}

func (h *handler) RevokeOtherSessions(ctx context.Context, _ *struct{}) (*statusOutput, error) {
	if err := h.Auth.RevokeOtherSessions(ctx, current(ctx)); err != nil {
		return nil, err
	}
	return statusOK(), nil
}

type updateSessionInput struct {
	Body map[string]any
}

type updateSessionOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Session dtos.SessionData `json:"session"`
	}
}

func (h *handler) UpdateSession(ctx context.Context, in *updateSessionInput) (*updateSessionOutput, error) {
	sw, err := h.Auth.UpdateSession(ctx, current(ctx), in.Body)
	if err != nil {
		return nil, err
	}
	out := &updateSessionOutput{SetCookie: h.sessionCookies(ctx, sw)}
	out.Body.Session = sw.Session
	return out, nil
}

// sessionCookies re-issues the session cookie for sw, keeping the request's rememberMe choice.
func (h *handler) sessionCookies(ctx context.Context, sw *dtos.SessionWithUser) []http.Cookie {
	if sw == nil {
		return nil
	}
	dontRemember := false
	if req := requestOf(ctx); req != nil {
		dontRemember = h.Cookies.DontRemember(req.Header.Get("Cookie"))
	}
	return h.Cookies.SessionCookies(sw.Session.Token, dontRemember)
}
