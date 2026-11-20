package services

import (
	"context"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/providers/cookies"
)

// AuthorizeFunc runs an authorization request (the oidc-provider's or the mcp plugin's authorize).
type AuthorizeFunc func(ctx context.Context, req AuthorizeRequest) *endpointhooks.Response

// ResumeAfterLogin is the oidc-provider's after hook (matcher: every endpoint): when a request carrying
// the signed oidc_login_prompt cookie signs the user in (its response sets the session cookie), the
// cookie is expired and the saved authorization request runs again for the new session, without
// prompt=login. Its answer (the redirect to the client or to the consent page) replaces the response;
// the cookies the response already sets (the session) are kept.
func (s *Service) ResumeAfterLogin(c *endpointhooks.Context, authorize AuthorizeFunc) (*endpointhooks.Response, error) {
	if c == nil || c.Returned == nil {
		return nil, nil
	}
	// Step 1: the saved authorization query and a response setting the session cookie
	cookieHeader := c.Headers.Get("Cookie")
	saved, ok := s.ReadFlowCookie(cookieHeader, LoginPromptCookie)
	if !ok {
		return nil, nil
	}
	token, setsSession := s.newSessionToken(c.Returned)
	if !setsSession {
		return nil, nil
	}
	// Step 2: the cookie is spent
	c.Returned.SetCookie(ptr(ExpiredFlowCookie(LoginPromptCookie)))
	// Step 3: the session the response hands out (an expired session cookie, e.g. sign-out, has none)
	if token == "" {
		return nil, nil
	}
	session := c.NewSession()
	if session == nil {
		if sw, err := s.deps.Kit.Sessions.Get(c.Ctx, token); err == nil {
			session = sw
		}
	}
	if session == nil {
		return nil, nil
	}
	query, ok := QueryFromJSON(saved)
	if !ok {
		return nil, nil
	}
	// Step 4: the user just logged in, so prompt=login is satisfied
	prompt, perr := ParsePrompt(query["prompt"])
	if perr != nil {
		return keepCookies(c.Returned, perr), nil
	}
	if prompt["login"] {
		query["prompt"] = PromptString(query["prompt"], "login")
	}
	// Step 5: authorize for the new session; its answer replaces the sign-in response
	res := authorize(c.Ctx, AuthorizeRequest{Query: query, Headers: c.Headers, Session: session})
	return keepCookies(c.Returned, res), nil
}

// newSessionToken returns the session token the response sets in the session_token cookie; sets reports
// whether the response writes that cookie at all (token is "" when it deletes it or the value is invalid).
func (s *Service) newSessionToken(res *endpointhooks.Response) (token string, sets bool) {
	name := s.deps.Kit.Cookies.Name(cookies.CookieSessionToken)
	for _, ck := range res.Cookies() {
		if ck.Name != name {
			continue
		}
		sets, token = true, ""
		if ck.MaxAge < 0 || ck.Value == "" {
			continue
		}
		if v, ok := s.deps.Kit.Cookies.Verify(cookies.DecodeCookieValue(ck.Value)); ok {
			token = v
		}
	}
	return token, sets
}

// keepCookies returns next with the Set-Cookie entries of prev in front of its own (better-auth merges the
// response headers set so far into whatever the hook returns).
func keepCookies(prev, next *endpointhooks.Response) *endpointhooks.Response {
	out := next.Clone()
	if out.Header == nil {
		out.Header = map[string][]string{}
	}
	own := out.Header.Values("Set-Cookie")
	out.Header.Del("Set-Cookie")
	for _, c := range prev.Header.Values("Set-Cookie") {
		out.Header.Add("Set-Cookie", c)
	}
	for _, c := range own {
		out.Header.Add("Set-Cookie", c)
	}
	return out
}

func ptr[T any](v T) *T { return &v }
