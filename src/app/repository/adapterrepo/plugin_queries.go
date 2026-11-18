package adapterrepo

import (
	"context"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/schema"
)

// Queries plugins run on the core models through the adapter (admin's user search, the organization
// plugin's member/inviter users), decoded into goauth's Go models.

// UserField resolves a user field name the way UpdateUser does (Go field name, registry field name or
// column) to its registry field name; ok is false when the registry has no such field (e.g. a plugin
// column of a plugin that is not installed).
func (r *Repos) UserField(name string) (string, bool) { return r.user.field(name) }

// FindUsers returns the live (not soft-deleted) users matching q, decoded into models.User.
func (r *Repos) FindUsers(ctx context.Context, q adapter.Query) ([]models.User, error) {
	q.Where = r.liveUser(q.Where...)
	return findMany[models.User](ctx, r, r.user, q)
}

// CountUsers counts the live users matching where.
func (r *Repos) CountUsers(ctx context.Context, where []adapter.Where) (int64, error) {
	n, err := r.a.Count(ctx, schema.ModelUser, r.liveUser(where...))
	if err != nil {
		return 0, wrap(schema.ModelUser, "count", err)
	}
	return n, nil
}

// FindUsersByIDs returns the live users with the given ids, keyed by id (unknown ids are left out).
func (r *Repos) FindUsersByIDs(ctx context.Context, ids []string) (map[string]models.User, error) {
	out := map[string]models.User{}
	// Step 1: unique, non-empty ids
	seen := map[string]bool{}
	var in []any
	for _, id := range ids {
		if id != "" && !seen[id] {
			seen[id] = true
			in = append(in, id)
		}
	}
	if len(in) == 0 {
		return out, nil
	}
	// Step 2: one query for all of them
	users, err := r.FindUsers(ctx, adapter.Query{Where: []adapter.Where{{Field: "id", Op: adapter.In, Value: in}}})
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		out[u.ID] = u
	}
	return out, nil
}

// FindSessions returns the sessions matching q, decoded into models.Session.
func (r *Repos) FindSessions(ctx context.Context, q adapter.Query) ([]models.Session, error) {
	return findMany[models.Session](ctx, r, r.session, q)
}
