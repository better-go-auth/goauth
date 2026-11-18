// Package services implements the custom-session after hooks: they replace the body of GET /get-session
// (and optionally of GET /multi-session/list-device-sessions) with the result of the user's callback.
package services

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/plugins/custom-session/config"
)

// Paths the plugin rewrites (relative to BasePath).
const (
	PathGetSession         = "/get-session"
	PathListDeviceSessions = "/multi-session/list-device-sessions"
)

// Service runs the custom-session callback on session responses.
type Service struct {
	cfg config.CustomSessionConfig
}

// New builds the service.
func New(cfg config.CustomSessionConfig) (*Service, error) {
	if cfg.Fn == nil {
		return nil, errors.New("custom-session: a callback (Fn) is required")
	}
	return &Service{cfg: cfg}, nil
}

// Hooks returns the plugin's after hooks: GET /get-session always, GET /multi-session/list-device-sessions
// with ShouldMutateListDeviceSessionsEndpoint (better-auth's matcher).
func (s *Service) Hooks() endpointhooks.Hooks {
	hooks := endpointhooks.Hooks{After: []endpointhooks.AfterHook{{
		Matcher: func(c *endpointhooks.Context) bool {
			return c.Path == PathGetSession && c.Method == http.MethodGet
		},
		Handler: s.getSession,
	}}}
	if s.cfg.ShouldMutateListDeviceSessionsEndpoint {
		hooks.After = append(hooks.After, endpointhooks.AfterHook{
			Matcher: endpointhooks.MatchPaths(PathListDeviceSessions),
			Handler: s.listDeviceSessions,
		})
	}
	return hooks
}

// getSession is better-auth's custom /get-session endpoint: no session stays null, otherwise the body is the
// callback's result. Cookies and headers of the core response (e.g. a refreshed session cookie) are kept.
func (s *Service) getSession(c *endpointhooks.Context) (*endpointhooks.Response, error) {
	// Step 1: only successful JSON answers carry a session
	res := c.Returned
	if res == nil || res.Status >= http.StatusMultipleChoices || !res.IsJSON() {
		return nil, nil
	}
	var raw map[string]any
	if err := json.Unmarshal(res.Body, &raw); err != nil || raw == nil {
		// null (no session) stays null
		return nil, nil
	}
	// Step 2: run the callback on the session
	out, err := s.run(c, res.Body, raw)
	if err != nil {
		return nil, err
	}
	// Step 3: the callback's value replaces the body
	res.SetJSON(out)
	return nil, nil
}

// listDeviceSessions maps every {session, user} of the multi-session list through the callback.
func (s *Service) listDeviceSessions(c *endpointhooks.Context) (*endpointhooks.Response, error) {
	// Step 1: better-auth's getEndpointResponse: only 200 responses
	res := c.Returned
	if res == nil || res.Status != http.StatusOK || !res.IsJSON() {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(res.Body, &items); err != nil || items == nil {
		return nil, nil
	}
	// Step 2: run the callback on every entry, in order
	out := make([]any, 0, len(items))
	for _, item := range items {
		var raw map[string]any
		if err := json.Unmarshal(item, &raw); err != nil || raw == nil {
			out = append(out, nil)
			continue
		}
		v, err := s.run(c, item, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	// Step 3: the mapped list replaces the body
	res.SetJSON(out)
	return nil, nil
}

// run decodes the typed session and calls the user's callback.
func (s *Service) run(c *endpointhooks.Context, body []byte, raw map[string]any) (any, error) {
	in := &config.Session{Raw: raw, Request: c.Request}
	var typed struct {
		Session json.RawMessage `json:"session"`
		User    json.RawMessage `json:"user"`
	}
	if err := json.Unmarshal(body, &typed); err == nil {
		_ = json.Unmarshal(typed.Session, &in.Session)
		_ = json.Unmarshal(typed.User, &in.User)
	}
	return s.cfg.Fn(c.Ctx, in)
}
