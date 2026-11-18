// Package endpointhooks holds the types of better-auth's endpoint hooks (`hooks.before` / `hooks.after` and a
// plugin's `hooks`). goauth runs them in one Huma middleware around every core and plugin route:
//
//	user before hook → plugin before hooks → endpoint → user after hook → goauth's built-in after hooks
//	(two-factor sign-in challenge, new-session hooks, OnResponse hooks) → plugin after hooks
//
// which is better-auth's order (dispatch.ts: the user hook first, then plugin hooks in plugin order).
//
// A before hook can change the request (Headers, Query, Body), answer instead of the endpoint (return a
// Response) or fail it (return an error: an *autherr.AuthError is sent as {code, message} with its status,
// any other error as 500 INTERNAL_SERVER_ERROR). An after hook sees the endpoint's response (Returned:
// status, headers including Set-Cookie, body) and the session created by the request (NewSession); it can
// change Returned in place, replace it (return a Response) or replace it with an error.
package endpointhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/better-go-auth/goauth/src/models/dtos"
)

// Context is the endpoint context a hook receives (better-auth's hook ctx).
type Context struct {
	// Ctx is the request context.
	Ctx context.Context
	// Path is the route path relative to BasePath, with Huma path parameters
	// (e.g. "/sign-in/email", "/reset-password/{token}"). better-auth writes parameters as ":token".
	Path string
	// Method is the HTTP method.
	Method string
	// Request is the incoming request. Its Header and URL reflect the changes of earlier before hooks.
	Request *http.Request
	// Headers are the request headers. Before hooks may change them; the endpoint sees the result.
	Headers http.Header
	// Query is the URL query. Before hooks may change it; the endpoint sees the result.
	Query url.Values
	// Body is the decoded JSON body when it is a JSON object (numbers as json.Number), nil otherwise.
	// Before hooks may change it in place or replace it with SetBody; the endpoint gets the result.
	Body map[string]any
	// ResponseHeaders are headers before hooks add to the final response, e.g. a cookie set with SetCookie
	// (better-auth's ctx.setCookie / ctx.setHeader in a before hook). Set-Cookie entries are appended,
	// other headers replace the endpoint's.
	ResponseHeaders http.Header
	// Returned is the endpoint's response (better-auth's ctx.context.returned); nil in before hooks.
	// After hooks may change it in place.
	Returned *Response

	newSession func() *dtos.SessionWithUser
}

// NewContext builds a hook context; newSession lazily returns the session created by the request
// (used by the HTTP layer that runs the hooks, and by tests).
func NewContext(ctx context.Context, path, method string, r *http.Request, newSession func() *dtos.SessionWithUser) *Context {
	c := &Context{Ctx: ctx, Path: path, Method: method, Request: r, ResponseHeaders: http.Header{}, newSession: newSession}
	if r != nil {
		c.Headers = r.Header.Clone()
		if r.URL != nil {
			c.Query = r.URL.Query()
		}
	}
	if c.Headers == nil {
		c.Headers = http.Header{}
	}
	if c.Query == nil {
		c.Query = url.Values{}
	}
	return c
}

// NewSession returns the session created while handling this request (better-auth's
// ctx.context.newSession): the session whose cookie the response sets. It is nil in before hooks and when
// the request created none.
func (c *Context) NewSession() *dtos.SessionWithUser {
	if c == nil || c.newSession == nil || c.Returned == nil {
		return nil
	}
	return c.newSession()
}

// SetBody replaces the request body with v (encoded as JSON). Only for before hooks.
func (c *Context) SetBody(v map[string]any) { c.Body = v }

// SetCookie adds a cookie to the final response: from a before hook it is merged into whatever answers
// the request, from an after hook it is added to Returned.
func (c *Context) SetCookie(cookie *http.Cookie) {
	if cookie == nil {
		return
	}
	if c.Returned != nil {
		c.Returned.SetCookie(cookie)
		return
	}
	c.ResponseHeaders.Add("Set-Cookie", cookie.String())
}

// Cookie returns the value of request cookie name ("" and false when missing).
func (c *Context) Cookie(name string) (string, bool) {
	r := &http.Request{Header: http.Header{"Cookie": c.Headers.Values("Cookie")}}
	ck, err := r.Cookie(name)
	if err != nil {
		return "", false
	}
	return ck.Value, true
}

// Response is an HTTP response produced by an endpoint or a hook.
type Response struct {
	// Status is the HTTP status (0 is sent as 200).
	Status int
	// Header holds the response headers, including Set-Cookie entries.
	Header http.Header
	// Body is the raw response body.
	Body []byte
}

// JSON returns a JSON response with v as body (better-auth's ctx.json).
func JSON(status int, v any) *Response {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return &Response{Status: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: buf.Bytes()}
}

// Redirect returns a 302 response to location (better-auth's ctx.redirect).
func Redirect(location string) *Response {
	return &Response{Status: http.StatusFound, Header: http.Header{"Location": {location}}}
}

// IsJSON reports whether the response declares a JSON body.
func (r *Response) IsJSON() bool {
	if r == nil {
		return false
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.HasPrefix(ct, "application/json") || strings.Contains(ct, "+json")
}

// DecodeJSON decodes the body into v.
func (r *Response) DecodeJSON(v any) error {
	return json.Unmarshal(r.Body, v)
}

// JSONBody returns the body decoded as a JSON object (nil when it is not one).
func (r *Response) JSONBody() map[string]any {
	if r == nil || len(r.Body) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		return nil
	}
	return m
}

// SetJSON replaces the body with v encoded as JSON and sets the JSON content type.
func (r *Response) SetJSON(v any) {
	next := JSON(r.Status, v)
	r.ensureHeader()
	r.Header.Set("Content-Type", "application/json")
	r.Body = next.Body
}

// Cookies returns the Set-Cookie entries of the response (unparsable ones are skipped).
func (r *Response) Cookies() []*http.Cookie {
	if r == nil {
		return nil
	}
	var out []*http.Cookie
	for _, raw := range r.Header.Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(raw); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// SetCookie appends a Set-Cookie entry.
func (r *Response) SetCookie(c *http.Cookie) {
	if c == nil {
		return
	}
	r.ensureHeader()
	r.Header.Add("Set-Cookie", c.String())
}

// RemoveCookies drops the Set-Cookie entries of the named cookies.
func (r *Response) RemoveCookies(names ...string) {
	if r == nil || len(names) == 0 {
		return
	}
	drop := map[string]bool{}
	for _, n := range names {
		drop[n] = true
	}
	var keep []string
	for _, raw := range r.Header.Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(raw); err == nil && drop[c.Name] {
			continue
		}
		keep = append(keep, raw)
	}
	r.Header.Del("Set-Cookie")
	for _, raw := range keep {
		r.Header.Add("Set-Cookie", raw)
	}
}

func (r *Response) ensureHeader() {
	if r.Header == nil {
		r.Header = http.Header{}
	}
}

// Clone returns a deep copy of the response.
func (r *Response) Clone() *Response {
	if r == nil {
		return nil
	}
	return &Response{Status: r.Status, Header: r.Header.Clone(), Body: append([]byte(nil), r.Body...)}
}

// BeforeFunc is a before hook. A non-nil Response answers the request instead of the endpoint; an error
// fails it; (nil, nil) continues with the (possibly changed) request.
type BeforeFunc func(c *Context) (*Response, error)

// AfterFunc is an after hook. A non-nil Response replaces c.Returned; an error replaces it with that
// error; (nil, nil) keeps c.Returned (including in-place changes).
type AfterFunc func(c *Context) (*Response, error)

// Matcher selects the requests a plugin hook runs on (better-auth's matcher(ctx)); nil matches all.
type Matcher func(c *Context) bool

// BeforeHook is a plugin before hook.
type BeforeHook struct {
	Matcher Matcher
	Handler BeforeFunc
}

// AfterHook is a plugin after hook.
type AfterHook struct {
	Matcher Matcher
	Handler AfterFunc
}

// Hooks are a plugin's endpoint hooks (better-auth's plugin `hooks: {before, after}`).
type Hooks struct {
	Before []BeforeHook
	After  []AfterHook
}

// Empty reports whether there are no hooks.
func (h Hooks) Empty() bool { return len(h.Before) == 0 && len(h.After) == 0 }

// MatchPaths matches requests whose Path is one of paths.
func MatchPaths(paths ...string) Matcher {
	set := make(map[string]bool, len(paths))
	for _, p := range paths {
		set[p] = true
	}
	return func(c *Context) bool { return set[c.Path] }
}

// MatchPrefix matches requests whose Path starts with one of prefixes.
func MatchPrefix(prefixes ...string) Matcher {
	return func(c *Context) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(c.Path, p) {
				return true
			}
		}
		return false
	}
}
