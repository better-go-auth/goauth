package ba

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/compat"
)

type getSessionInput struct {
	DisableCookieCache bool   `query:"disableCookieCache" doc:"Bypass the cookie cache (no-op until the cookie cache is implemented)"`
	DisableRefresh     bool   `query:"disableRefresh" doc:"Do not extend the session expiry"`
	Cookie             string `header:"Cookie"`
}

type getSessionBody struct {
	compat.SessionWithUser
	NeedsRefresh *bool `json:"needsRefresh,omitempty"`
}

type getSessionOutput struct {
	CacheControl string        `header:"Cache-Control"`
	Pragma       string        `header:"Pragma"`
	SetCookie    []http.Cookie `header:"Set-Cookie"`
	// nil is written as JSON null, which is what better-auth returns without a session
	Body *getSessionBody
}

func (h *handler) getSession(ctx context.Context, in *getSessionInput) (*getSessionOutput, error) {
	return h.session(ctx, in, h.Conf.Session.DeferSessionRefresh)
}

func (h *handler) postSession(ctx context.Context, in *getSessionInput) (*getSessionOutput, error) {
	if !h.Conf.Session.DeferSessionRefresh {
		return nil, compat.ErrMethodNotAllowedDeferSessionRequired
	}
	return h.session(ctx, in, false)
}

// session mirrors better-auth's getSession endpoint; when deferRefresh is set it reports needsRefresh instead of writing.
func (h *handler) session(ctx context.Context, in *getSessionInput, deferRefresh bool) (*getSessionOutput, error) {
	out := &getSessionOutput{CacheControl: "no-store", Pragma: "no-cache"}

	tok, ok := h.Cookies.SessionToken(in.Cookie)
	if !ok {
		return out, nil
	}
	sw, err := h.Sessions.Get(ctx, tok)
	if err != nil {
		return nil, compat.ErrFailedToGetSession
	}
	if sw == nil {
		out.SetCookie = h.Cookies.ExpireSessionCookies()
		return out, nil
	}

	dontRemember := h.Cookies.DontRemember(in.Cookie)
	needsRefresh := !in.DisableRefresh && h.Sessions.ShouldRefresh(sw, dontRemember)
	if deferRefresh {
		out.Body = &getSessionBody{SessionWithUser: *sw, NeedsRefresh: &needsRefresh}
		return out, nil
	}
	if needsRefresh {
		refreshed, err := h.Sessions.Refresh(ctx, sw)
		if err != nil {
			return nil, compat.ErrFailedToGetSession
		}
		if refreshed == nil {
			out.SetCookie = h.Cookies.ExpireSessionCookies()
			return nil, compat.ErrFailedToGetSession.WithStatus(http.StatusUnauthorized)
		}
		sw = refreshed
		out.SetCookie = h.Cookies.SessionCookies(tok, false)
	}
	out.Body = &getSessionBody{SessionWithUser: *sw}
	return out, nil
}
