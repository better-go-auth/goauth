package repotest

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// ExtraFields returns the additionalFields RunExtraFields needs, as per-model schema options: the
// repositories under test must be built on a registry with them.
func ExtraFields() map[string]schema.ModelOptions {
	return map[string]schema.ModelOptions{
		schema.ModelUser: {AdditionalFields: map[string]schema.Field{
			"loyaltyTier": {Type: schema.String, Default: "bronze"},
			"birthday":    {Type: schema.Date},
			"tags":        {Type: schema.StringArray},
			"score":       {Type: schema.Number},
		}},
		schema.ModelSession: {AdditionalFields: map[string]schema.Field{
			"region": {Type: schema.String},
		}},
		schema.ModelAccount: {AdditionalFields: map[string]schema.Field{
			"tenant": {Type: schema.String, Default: "main"},
		}},
	}
}

// RunExtraFields checks that additional fields (models' Extra map) round-trip through create, find, list
// and update for users, sessions and accounts. Only repositories built on the schema registry (adapterrepo)
// support them.
func RunExtraFields(t *testing.T, newRepos Factory) {
	t.Run("user extra fields", func(t *testing.T) { testUserExtra(t, newRepos(t)) })
	t.Run("session extra fields", func(t *testing.T) { testSessionExtra(t, newRepos(t)) })
	t.Run("account extra fields", func(t *testing.T) { testAccountExtra(t, newRepos(t)) })
}

func testUserExtra(t *testing.T, r repo_interfaces.IAuthRepos) {
	ctx := context.Background()
	birthday := time.Date(1990, 5, 17, 0, 0, 0, 0, time.UTC)
	// Step 1: create with extras; the default of loyaltyTier is applied
	u := newUser("extra@example.com")
	schema.Set(u, "birthday", birthday)
	schema.Set(u, "tags", []string{"beta", "vip"})
	created, err := r.CreateUser(ctx, u)
	require.NoError(t, err)
	tier, ok := schema.Get[string](created, "loyaltyTier")
	require.True(t, ok)
	require.Equal(t, "bronze", tier)
	got, ok := schema.Get[time.Time](created, "birthday")
	require.True(t, ok)
	require.True(t, birthday.Equal(got))

	// Step 2: lookups return them
	found, err := r.FindUserByEmail(ctx, "extra@example.com")
	require.NoError(t, err)
	tags, ok := schema.Get[[]string](found, "tags")
	require.True(t, ok)
	require.Equal(t, []string{"beta", "vip"}, tags)
	_, ok = schema.Get[float64](found, "score")
	require.False(t, ok, "unset extras are absent")

	// Step 3: update by field name, static and extra fields together
	updated, err := r.UpdateUser(ctx, created.ID, map[string]interface{}{"loyaltyTier": "gold", "score": 4.5, "Name": "Extra"})
	require.NoError(t, err)
	require.Equal(t, "Extra", updated.Name)
	tier, _ = schema.Get[string](updated, "loyaltyTier")
	require.Equal(t, "gold", tier)
	score, _ := schema.Get[float64](updated, "score")
	require.Equal(t, 4.5, score)

	// Step 4: lists return them; clearing a value removes it
	users, _, err := r.ListUsers(ctx, repo_interfaces.UserFilter{}, dtos.PaginationInput{})
	require.NoError(t, err)
	require.Len(t, users, 1)
	tier, _ = schema.Get[string](&users[0], "loyaltyTier")
	require.Equal(t, "gold", tier)
	cleared, err := r.UpdateUser(ctx, created.ID, map[string]interface{}{"tags": nil})
	require.NoError(t, err)
	_, ok = schema.Get[[]string](cleared, "tags")
	require.False(t, ok)

	// Step 5: undeclared fields are rejected
	bad := newUser("bad@example.com")
	schema.Set(bad, "undeclared", 1)
	_, err = r.CreateUser(ctx, bad)
	require.Error(t, err)
	_, err = r.UpdateUser(ctx, created.ID, map[string]interface{}{"undeclared": 1})
	require.Error(t, err)
}

func testSessionExtra(t *testing.T, r repo_interfaces.IAuthRepos) {
	ctx := context.Background()
	u := mustCreateUser(t, r, "sx@example.com")
	// Step 1: create with an extra
	s := newSession(u.ID, "extra-token", time.Hour)
	schema.Set(s, "region", "eu")
	created, err := r.CreateSession(ctx, s)
	require.NoError(t, err)
	region, _ := schema.Get[string](created, "region")
	require.Equal(t, "eu", region)

	// Step 2: find and update
	found, err := r.FindSession(ctx, "extra-token")
	require.NoError(t, err)
	region, _ = schema.Get[string](found, "region")
	require.Equal(t, "eu", region)
	updated, err := r.UpdateSession(ctx, created.ID, map[string]interface{}{"region": "us"})
	require.NoError(t, err)
	region, _ = schema.Get[string](updated, "region")
	require.Equal(t, "us", region)
	list, err := r.ListSessions(ctx, u.ID)
	require.NoError(t, err)
	region, _ = schema.Get[string](&list[0], "region")
	require.Equal(t, "us", region)
}

func testAccountExtra(t *testing.T, r repo_interfaces.IAuthRepos) {
	ctx := context.Background()
	u := mustCreateUser(t, r, "ax@example.com")
	// Step 1: create without the extra: its default is stored
	acc, err := r.CreateAccount(ctx, &models.Account{UserID: u.ID, AccountID: "gh-x", ProviderID: models.ProvGithub})
	require.NoError(t, err)
	tenant, _ := schema.Get[string](acc, "tenant")
	require.Equal(t, "main", tenant)

	// Step 2: update and read back
	_, err = r.UpdateAccount(ctx, acc.ID, map[string]interface{}{"tenant": "acme"})
	require.NoError(t, err)
	all, err := r.FindAccounts(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, all, 1)
	tenant, _ = schema.Get[string](&all[0], "tenant")
	require.Equal(t, "acme", tenant)
	found, err := r.FindAccountByProviderID(ctx, models.ProvGithub, "gh-x")
	require.NoError(t, err)
	tenant, _ = schema.Get[string](found, "tenant")
	require.Equal(t, "acme", tenant)
}
