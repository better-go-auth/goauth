package session

import (
	"context"
	"sync"

	"github.com/better-go-auth/goauth/src/models/dtos"
)

// newSessionsKey is the context key of the per-request NewSessionRecorder.
type newSessionsKey struct{}

// NewSessionRecorder collects the sessions Manager.Create made while handling one request
// (better-auth's ctx.context.newSession). The HTTP layer installs it with WithNewSessionRecorder and
// fires plugins.NewSessionEvent hooks for the session the response hands out.
type NewSessionRecorder struct {
	mu       sync.Mutex
	sessions []*dtos.SessionWithUser
}

// WithNewSessionRecorder returns ctx carrying a fresh recorder.
func WithNewSessionRecorder(ctx context.Context) (context.Context, *NewSessionRecorder) {
	rec := &NewSessionRecorder{}
	return context.WithValue(ctx, newSessionsKey{}, rec), rec
}

// Find returns the recorded session with token, or nil.
func (r *NewSessionRecorder) Find(token string) *dtos.SessionWithUser {
	if r == nil || token == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.sessions) - 1; i >= 0; i-- {
		if r.sessions[i].Session.Token == token {
			return r.sessions[i]
		}
	}
	return nil
}

// recordNewSession remembers sw on the request's recorder, if ctx has one.
func recordNewSession(ctx context.Context, sw *dtos.SessionWithUser) {
	rec, _ := ctx.Value(newSessionsKey{}).(*NewSessionRecorder)
	if rec == nil || sw == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.sessions = append(rec.sessions, sw)
}
