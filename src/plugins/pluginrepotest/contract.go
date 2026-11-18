// Package pluginrepotest holds the contract the repositories of goauth's storage plugins (two-factor,
// passkey, jwt, organization, admin) must pass on every storage adapter, like repotest for the core
// repositories. Run it with an adapter over Registry (memory, GORM on SQLite / Postgres / MySQL, ...).
package pluginrepotest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	"github.com/better-go-auth/goauth/src/plugins/admin/repository/adapteradmin"
	jwtmodels "github.com/better-go-auth/goauth/src/plugins/jwt/models"
	jwtrepo "github.com/better-go-auth/goauth/src/plugins/jwt/repository"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
	"github.com/better-go-auth/goauth/src/plugins/org/repository/adapterorg"
	pkmodels "github.com/better-go-auth/goauth/src/plugins/passkey/models"
	pkrepo "github.com/better-go-auth/goauth/src/plugins/passkey/repository"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	tfmodels "github.com/better-go-auth/goauth/src/plugins/two-factor/models"
	tfrepo "github.com/better-go-auth/goauth/src/plugins/two-factor/repository"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// Registry returns the core schema plus every storage plugin's schema (organization with teams and dynamic
// access control, two-factor, passkey, jwt), for one contract run.
func Registry(opts schema.Options) *schema.Registry {
	opts.Plugins = append(opts.Plugins,
		schema.Plugin{ID: "org", Schema: orgmodels.Schema(true, true)},
		schema.Plugin{ID: "two-factor", Schema: tfmodels.Schema()},
		schema.Plugin{ID: "passkey", Schema: pkmodels.Schema()},
		schema.Plugin{ID: "jwt", Schema: jwtmodels.Schema()},
	)
	return schema.MustBuild(opts)
}

// Env is one empty store for a subtest: an adapter over Schema (a registry built with Registry).
type Env struct {
	Adapter adapter.Adapter
	Schema  *schema.Registry
}

// Factory returns a fresh, empty store for one subtest.
type Factory func(t *testing.T) Env

// Run executes the plugin repository contract against the stores built by newEnv.
func Run(t *testing.T, newEnv Factory) {
	t.Run("two-factor", func(t *testing.T) { testTwoFactor(t, newEnv(t)) })
	t.Run("two-factor backup code swap is atomic", func(t *testing.T) { testTwoFactorSwapRace(t, newEnv(t)) })
	t.Run("passkey", func(t *testing.T) { testPasskey(t, newEnv(t)) })
	t.Run("jwks", func(t *testing.T) { testJWKS(t, newEnv(t)) })
	t.Run("organizations", func(t *testing.T) { testOrganizations(t, newEnv(t)) })
	t.Run("members", func(t *testing.T) { testMembers(t, newEnv(t)) })
	t.Run("invitations", func(t *testing.T) { testInvitations(t, newEnv(t)) })
	t.Run("teams", func(t *testing.T) { testTeams(t, newEnv(t)) })
	t.Run("organization roles", func(t *testing.T) { testRoles(t, newEnv(t)) })
	t.Run("delete organization", func(t *testing.T) { testDeleteOrganization(t, newEnv(t)) })
	t.Run("admin users", func(t *testing.T) { testAdminUsers(t, newEnv(t)) })
	t.Run("admin list users", func(t *testing.T) { testAdminListUsers(t, newEnv(t)) })
	t.Run("admin sessions", func(t *testing.T) { testAdminSessions(t, newEnv(t)) })
	t.Run("admin remove user", func(t *testing.T) { testAdminRemoveUser(t, newEnv(t)) })
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// core returns the core repositories on the env's adapter (users, sessions and accounts the plugin rows
// reference).
func core(t *testing.T, env Env) *adapterrepo.Repos {
	t.Helper()
	r, err := adapterrepo.New(env.Adapter, env.Schema)
	require.NoError(t, err)
	return r
}

// user creates a user (email, name) and returns it.
func user(t *testing.T, env Env, email, name string) *models.User {
	t.Helper()
	u, err := core(t, env).CreateUser(context.Background(), &models.User{UserDto: models.UserDto{Name: name, Email: email, Role: enums.User}})
	require.NoError(t, err)
	require.NotEmpty(t, u.ID)
	return u
}

// ms truncates to the millisecond precision every backend stores.
func ms(tm time.Time) time.Time { return schema.DateMillis(tm) }

func str(s string) *string { return &s }

// ─── two-factor ──────────────────────────────────────────────────────────────

func testTwoFactor(t *testing.T, env Env) {
	ctx := context.Background()
	repo, err := tfrepo.New(env.Adapter, env.Schema)
	require.NoError(t, err)
	u := user(t, env, "tf@example.com", "TF")

	// Step 1: nothing stored yet
	row, err := repo.FindByUserID(ctx, u.ID)
	require.NoError(t, err)
	require.Nil(t, row)

	// Step 2: create (the id is generated and handed back; verified=false is stored, not the default)
	created := &tfmodels.TwoFactor{Secret: "secret", BackupCodes: `["a","b"]`, UserID: u.ID}
	require.NoError(t, repo.Create(ctx, created))
	require.NotEmpty(t, created.ID)
	row, err = repo.FindByUserID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, *created, *row)
	require.False(t, row.Verified)

	// Step 3: updates
	require.NoError(t, repo.SetVerified(ctx, row.ID))
	require.NoError(t, repo.UpdateBackupCodes(ctx, row.ID, `["c"]`))
	row, err = repo.FindByUserID(ctx, u.ID)
	require.NoError(t, err)
	require.True(t, row.Verified)
	require.Equal(t, `["c"]`, row.BackupCodes)

	// Step 4: compare-and-swap of the backup codes
	ok, err := repo.SwapBackupCodes(ctx, row.ID, `["stale"]`, `["x"]`)
	require.NoError(t, err)
	require.False(t, ok, "a stale value must not be replaced")
	ok, err = repo.SwapBackupCodes(ctx, row.ID, `["c"]`, `["d"]`)
	require.NoError(t, err)
	require.True(t, ok)
	row, err = repo.FindByUserID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, `["d"]`, row.BackupCodes)

	// Step 5: delete only touches the user's rows
	other := user(t, env, "tf2@example.com", "TF2")
	require.NoError(t, repo.Create(ctx, &tfmodels.TwoFactor{Secret: "s2", BackupCodes: "[]", UserID: other.ID, Verified: true}))
	require.NoError(t, repo.DeleteByUserID(ctx, u.ID))
	row, err = repo.FindByUserID(ctx, u.ID)
	require.NoError(t, err)
	require.Nil(t, row)
	row, err = repo.FindByUserID(ctx, other.ID)
	require.NoError(t, err)
	require.NotNil(t, row)
	require.True(t, row.Verified)
}

func testTwoFactorSwapRace(t *testing.T, env Env) {
	ctx := context.Background()
	repo, err := tfrepo.New(env.Adapter, env.Schema)
	require.NoError(t, err)
	u := user(t, env, "race@example.com", "Race")
	row := &tfmodels.TwoFactor{Secret: "s", BackupCodes: "v0", UserID: u.ID}
	require.NoError(t, repo.Create(ctx, row))

	// every goroutine tries to consume the same value: exactly one wins
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := repo.SwapBackupCodes(ctx, row.ID, "v0", fmt.Sprintf("v%d", i+1))
			if err == nil && ok {
				wins.Add(1)
			}
		}(i)
	}
	wg.Wait()
	require.Equal(t, int32(1), wins.Load())
}

// ─── passkey ─────────────────────────────────────────────────────────────────

func testPasskey(t *testing.T, env Env) {
	ctx := context.Background()
	repo, err := pkrepo.New(env.Adapter, env.Schema)
	require.NoError(t, err)
	u := user(t, env, "pk@example.com", "PK")
	other := user(t, env, "pk2@example.com", "PK2")

	// Step 1: unknown lookups are (nil, nil)
	for _, find := range []func() (*pkmodels.Passkey, error){
		func() (*pkmodels.Passkey, error) { return repo.FindByID(ctx, "missing") },
		func() (*pkmodels.Passkey, error) { return repo.FindByCredentialID(ctx, "missing") },
	} {
		pk, err := find()
		require.NoError(t, err)
		require.Nil(t, pk)
	}

	// Step 2: two passkeys of the user (optional fields set on one only), one of another user
	t1, t2 := ms(time.Now().Add(-time.Hour)), ms(time.Now())
	full := &pkmodels.Passkey{Name: str("laptop"), PublicKey: "pub1", UserID: u.ID, CredentialID: "cred-1", Counter: 3,
		DeviceType: "multiDevice", BackedUp: true, Transports: str("internal,hybrid"), CreatedAt: &t1, AAGUID: str("aaguid-1")}
	bare := &pkmodels.Passkey{PublicKey: "pub2", UserID: u.ID, CredentialID: "cred-2", DeviceType: "singleDevice", CreatedAt: &t2}
	for _, pk := range []*pkmodels.Passkey{bare, full, {PublicKey: "pub3", UserID: other.ID, CredentialID: "cred-3", DeviceType: "singleDevice", CreatedAt: &t2}} {
		require.NoError(t, repo.Create(ctx, pk))
		require.NotEmpty(t, pk.ID)
	}

	// Step 3: lookups return every field as stored
	got, err := repo.FindByCredentialID(ctx, "cred-1")
	require.NoError(t, err)
	require.Equal(t, *full, *got)
	got, err = repo.FindByID(ctx, bare.ID)
	require.NoError(t, err)
	require.Nil(t, got.Name)
	require.Nil(t, got.Transports)
	require.Nil(t, got.AAGUID)
	require.False(t, got.BackedUp)

	// Step 4: the user's passkeys, oldest first
	list, err := repo.ListByUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, full.ID, list[0].ID)
	require.Equal(t, bare.ID, list[1].ID)
	none, err := repo.ListByUser(ctx, "nobody")
	require.NoError(t, err)
	require.NotNil(t, none)
	require.Empty(t, none)

	// Step 5: counter and rename (rename of a missing passkey returns nil)
	require.NoError(t, repo.UpdateCounter(ctx, full.ID, 42))
	renamed, err := repo.UpdateName(ctx, full.ID, "desktop")
	require.NoError(t, err)
	require.Equal(t, "desktop", *renamed.Name)
	require.Equal(t, int64(42), renamed.Counter)
	missing, err := repo.UpdateName(ctx, "missing", "x")
	require.NoError(t, err)
	require.Nil(t, missing)

	// Step 6: deletes
	require.NoError(t, repo.Delete(ctx, bare.ID))
	got, err = repo.FindByID(ctx, bare.ID)
	require.NoError(t, err)
	require.Nil(t, got)
	require.NoError(t, repo.DeleteByUser(ctx, u.ID))
	list, err = repo.ListByUser(ctx, u.ID)
	require.NoError(t, err)
	require.Empty(t, list)
	list, err = repo.ListByUser(ctx, other.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
}

// ─── jwks ────────────────────────────────────────────────────────────────────

func testJWKS(t *testing.T, env Env) {
	ctx := context.Background()
	repo, err := jwtrepo.New(env.Adapter, env.Schema)
	require.NoError(t, err)

	// Step 1: empty
	latest, err := repo.GetLatestKey(ctx)
	require.NoError(t, err)
	require.Nil(t, latest)
	all, err := repo.GetAllKeys(ctx)
	require.NoError(t, err)
	require.Empty(t, all)

	// Step 2: an older key with an expiry and algorithm, a newer one without
	exp := ms(time.Now().Add(24 * time.Hour))
	older := &jwtmodels.JWK{PublicKey: "pub-old", PrivateKey: "priv-old", CreatedAt: ms(time.Now().Add(-time.Hour)), ExpiresAt: &exp, Alg: "ES256", Crv: "P-256"}
	newer := &jwtmodels.JWK{PublicKey: "pub-new", PrivateKey: "priv-new", CreatedAt: ms(time.Now())}
	require.NoError(t, repo.CreateJWK(ctx, older))
	require.NoError(t, repo.CreateJWK(ctx, newer))
	require.NotEmpty(t, older.ID)
	require.NotEqual(t, older.ID, newer.ID)

	// Step 3: newest first, every field kept
	all, err = repo.GetAllKeys(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
	require.Equal(t, *newer, all[0])
	require.Equal(t, *older, all[1])
	latest, err = repo.GetLatestKey(ctx)
	require.NoError(t, err)
	require.Equal(t, newer.ID, latest.ID)
	require.Nil(t, latest.ExpiresAt)
}

// ─── organization ────────────────────────────────────────────────────────────

func orgRepos(t *testing.T, env Env) orgrepo.OrgRepositories {
	t.Helper()
	repos, err := adapterorg.NewRepos(env.Adapter, env.Schema)
	require.NoError(t, err)
	require.NotNil(t, repos.ITeamRepo)
	require.NotNil(t, repos.IOrganizationRoleRepo)
	return repos
}

// org creates an organization.
func org(t *testing.T, repos orgrepo.OrgRepositories, name, slug, createdBy string, status orgmodels.OrgStatus) *orgmodels.Organization {
	t.Helper()
	o, err := repos.CreateOrg(context.Background(), &orgmodels.Organization{
		Base: models.Base{CreatedAt: ms(time.Now())}, Name: name, Slug: slug, CreatedBy: createdBy, Status: status,
	})
	require.NoError(t, err)
	require.NotEmpty(t, o.ID)
	return o
}

// member adds userID to orgID with role.
func member(t *testing.T, repos orgrepo.OrgRepositories, orgID, userID string, role orgmodels.OrgMemberRole) *orgmodels.Member {
	t.Helper()
	m, err := repos.CreateMember(context.Background(), &orgmodels.Member{
		Base: models.Base{CreatedAt: ms(time.Now())}, OrganizationID: orgID, UserID: userID, Role: role,
	})
	require.NoError(t, err)
	require.NotEmpty(t, m.ID)
	return m
}

func testOrganizations(t *testing.T, env Env) {
	ctx := context.Background()
	repos := orgRepos(t, env)
	owner := user(t, env, "owner@example.com", "Owner")

	// Step 1: create and read back
	acme := org(t, repos, "Acme Corp", "acme", owner.ID, orgmodels.OrgStatusActive)
	require.False(t, acme.CreatedAt.IsZero())
	got, err := repos.GetOrgByID(ctx, acme.ID)
	require.NoError(t, err)
	require.Equal(t, "acme", got.Slug)
	require.Equal(t, owner.ID, got.CreatedBy)
	require.Equal(t, orgmodels.OrgStatusActive, got.Status)
	got, err = repos.GetOrgBySlug(ctx, "acme")
	require.NoError(t, err)
	require.Equal(t, acme.ID, got.ID)
	for _, find := range []func() (*orgmodels.Organization, error){
		func() (*orgmodels.Organization, error) { return repos.GetOrgByID(ctx, "missing") },
		func() (*orgmodels.Organization, error) { return repos.GetOrgBySlug(ctx, "missing") },
		func() (*orgmodels.Organization, error) { return repos.GetOrgByID(ctx, "") },
	} {
		o, err := find()
		require.True(t, pluginkit.IsNotFound(err), "%v", err)
		require.Nil(t, o)
	}

	// Step 2: slugs are unique; the status defaults to active
	_, err = repos.CreateOrg(ctx, &orgmodels.Organization{Name: "Dup", Slug: "acme"})
	require.Error(t, err)
	beta, err := repos.CreateOrg(ctx, &orgmodels.Organization{Name: "Beta Labs", Slug: "beta"})
	require.NoError(t, err)
	require.Equal(t, orgmodels.OrgStatusActive, beta.Status)

	// Step 3: updates by Go field names (what the services pass), pointers included
	time.Sleep(5 * time.Millisecond)
	orgType := "enterprise"
	updated, err := repos.UpdateOrg(ctx, acme.ID, map[string]any{
		"Name": "Acme Inc", "Status": string(orgmodels.OrgStatusSuspended), "Metadata": `{"tier":"gold"}`, "OrgType": &orgType, "Logo": "https://logo",
	})
	require.NoError(t, err)
	require.Equal(t, "Acme Inc", updated.Name)
	require.Equal(t, orgmodels.OrgStatusSuspended, updated.Status)
	require.Equal(t, `{"tier":"gold"}`, *updated.Metadata)
	require.Equal(t, "enterprise", *updated.OrgType)
	require.Equal(t, "https://logo", *updated.Logo)
	require.True(t, updated.UpdatedAt.After(acme.CreatedAt), "updatedAt follows the update")
	_, err = repos.UpdateOrg(ctx, acme.ID, map[string]any{"NoSuchField": 1})
	require.Error(t, err)

	// Step 4: organizations of a user (through members)
	member(t, repos, acme.ID, owner.ID, orgmodels.OrgRoleOwner)
	member(t, repos, beta.ID, owner.ID, orgmodels.OrgRoleMember)
	mine, err := repos.ListOrgsByUserID(ctx, owner.ID)
	require.NoError(t, err)
	require.Len(t, mine, 2)
	none, err := repos.ListOrgsByUserID(ctx, "nobody")
	require.NoError(t, err)
	require.Empty(t, none)

	// Step 5: admin search: status filter, case-insensitive name/slug search, sort, page, total
	for i := 0; i < 3; i++ {
		org(t, repos, fmt.Sprintf("Gamma %d", i), fmt.Sprintf("gamma-%d", i), "", orgmodels.OrgStatusPending)
	}
	pending := orgmodels.OrgStatusPending
	list, total, err := repos.SearchAllOrgs(ctx, &pending, "", orgmodels.Pagination{Limit: 2, SortBy: "name", SortDir: "asc"})
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, list, 2)
	require.Equal(t, "Gamma 0", list[0].Name)
	list, _, err = repos.SearchAllOrgs(ctx, &pending, "", orgmodels.Pagination{Limit: 2, Offset: 2, SortBy: "name", SortDir: "asc"})
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "Gamma 2", list[0].Name)
	list, total, err = repos.SearchAllOrgs(ctx, nil, "ACME", orgmodels.Pagination{})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, acme.ID, list[0].ID)
	list, total, err = repos.SearchAllOrgs(ctx, nil, "bet", orgmodels.Pagination{})
	require.NoError(t, err)
	require.EqualValues(t, 1, total, "the slug matches too")
	require.Equal(t, beta.ID, list[0].ID)
	all, total, err := repos.ListAllOrgs(ctx, nil, orgmodels.Pagination{SortBy: "createdAt", SortDir: "asc"})
	require.NoError(t, err)
	require.EqualValues(t, 5, total)
	require.Len(t, all, 5)
	// a wildcard character in the search is matched literally
	_, total, err = repos.SearchAllOrgs(ctx, nil, "%", orgmodels.Pagination{})
	require.NoError(t, err)
	require.Zero(t, total)
}

func testMembers(t *testing.T, env Env) {
	ctx := context.Background()
	repos := orgRepos(t, env)
	alice := user(t, env, "alice@example.com", "Alice")
	bob := user(t, env, "bob@example.com", "Bob")
	carol := user(t, env, "carol@example.com", "Carol")
	o := org(t, repos, "Org", "org", alice.ID, orgmodels.OrgStatusActive)

	// Step 1: members come back with their user
	ma := member(t, repos, o.ID, alice.ID, orgmodels.OrgRoleOwner)
	time.Sleep(2 * time.Millisecond)
	mb := member(t, repos, o.ID, bob.ID, orgmodels.OrgRoleMember)
	time.Sleep(2 * time.Millisecond)
	member(t, repos, o.ID, carol.ID, orgmodels.OrgMemberRole("admin,sale"))
	got, err := repos.GetMemberByOrgAndUser(ctx, o.ID, bob.ID)
	require.NoError(t, err)
	require.Equal(t, mb.ID, got.ID)
	require.Equal(t, orgmodels.OrgRoleMember, got.Role)
	require.NotNil(t, got.User)
	require.Equal(t, "bob@example.com", got.User.Email)
	got, err = repos.GetMemberByID(ctx, ma.ID)
	require.NoError(t, err)
	require.Equal(t, "Alice", got.User.Name)
	_, err = repos.GetMemberByOrgAndUser(ctx, o.ID, "nobody")
	require.True(t, pluginkit.IsNotFound(err), "%v", err)

	// Step 2: update the role (Go field name)
	got, err = repos.UpdateMember(ctx, mb.ID, map[string]any{"Role": "admin"})
	require.NoError(t, err)
	require.Equal(t, orgmodels.OrgRoleAdmin, got.Role)
	require.NotNil(t, got.User)

	// Step 3: list: newest first by default, better-auth sortBy names, pages, users attached
	list, total, err := repos.ListMembersByOrgID(ctx, o.ID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, list, 3)
	require.Equal(t, carol.ID, list[0].UserID)
	for _, m := range list {
		require.NotNil(t, m.User)
	}
	list, _, err = repos.ListMembersByOrgID(ctx, o.ID, orgmodels.Pagination{Limit: 1, Offset: 1, SortBy: "createdAt", SortDir: "asc"})
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, bob.ID, list[0].UserID)
	list, _, err = repos.ListMembersByOrgID(ctx, o.ID, orgmodels.Pagination{SortBy: "role", SortDir: "asc"})
	require.NoError(t, err)
	require.Equal(t, []orgmodels.OrgMemberRole{"admin", "admin,sale", "owner"}, []orgmodels.OrgMemberRole{list[0].Role, list[1].Role, list[2].Role})

	// Step 4: deletes
	require.NoError(t, repos.DeleteMemberByOrgAndUser(ctx, o.ID, carol.ID))
	require.NoError(t, repos.DeleteMemberByID(ctx, mb.ID))
	_, total, err = repos.ListMembersByOrgID(ctx, o.ID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
}

func testInvitations(t *testing.T, env Env) {
	ctx := context.Background()
	repos := orgRepos(t, env)
	inviter := user(t, env, "inviter@example.com", "Inviter")
	invitee := user(t, env, "invitee@example.com", "Invitee")
	o := org(t, repos, "Org", "org", inviter.ID, orgmodels.OrgStatusActive)
	o2 := org(t, repos, "Other", "other", inviter.ID, orgmodels.OrgStatusActive)
	team, err := repos.CreateTeam(ctx, &orgmodels.Team{Name: "T", OrganizationID: o.ID})
	require.NoError(t, err)

	// Step 1: create; the status defaults to pending
	inv, err := repos.CreateInvitation(ctx, &orgmodels.Invitation{
		OrganizationID: o.ID, Email: "Invitee@Example.com", Role: orgmodels.OrgRoleAdmin, TeamID: &team.ID,
		ExpiresAt: ms(time.Now().Add(time.Hour)), InviterID: inviter.ID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, inv.ID)
	require.Equal(t, orgmodels.InvitationPending, inv.Status)
	expired, err := repos.CreateInvitation(ctx, &orgmodels.Invitation{
		OrganizationID: o2.ID, Email: "invitee@example.com", Role: orgmodels.OrgRoleMember, Status: orgmodels.InvitationPending,
		ExpiresAt: ms(time.Now().Add(-time.Hour)), InviterID: inviter.ID,
	})
	require.NoError(t, err)

	// Step 2: read back with organization and inviter
	got, err := repos.GetInvitationByID(ctx, inv.ID)
	require.NoError(t, err)
	require.Equal(t, team.ID, *got.TeamID)
	require.NotNil(t, got.Organization)
	require.Equal(t, "org", got.Organization.Slug)
	require.NotNil(t, got.Inviter)
	require.Equal(t, "inviter@example.com", got.Inviter.Email)
	_, err = repos.GetInvitationByID(ctx, "missing")
	require.True(t, pluginkit.IsNotFound(err), "%v", err)

	// Step 3: pending invitation of an email (case-insensitive), count, inbox (pending, unexpired)
	got, err = repos.GetInvitationByOrgAndEmail(ctx, o.ID, "INVITEE@example.com")
	require.NoError(t, err)
	require.Equal(t, inv.ID, got.ID)
	n, err := repos.CountPendingInvitationsByOrgID(ctx, o.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	inbox, err := repos.ListInvitationsByEmail(ctx, "invitee@EXAMPLE.com")
	require.NoError(t, err)
	require.Len(t, inbox, 1, "the expired invitation is left out")
	require.Equal(t, inv.ID, inbox[0].ID)
	require.Equal(t, "Org", inbox[0].Organization.Name)
	require.Equal(t, "Inviter", inbox[0].Inviter.Name)

	// Step 4: accept (goauth's acceptedById / acceptedAt); no pending invitation is left
	at := ms(time.Now())
	got, err = repos.UpdateInvitation(ctx, inv.ID, map[string]any{
		"Status": string(orgmodels.InvitationAccepted), "AcceptedByID": &invitee.ID, "AcceptedAt": &at,
	})
	require.NoError(t, err)
	require.Equal(t, orgmodels.InvitationAccepted, got.Status)
	require.Equal(t, invitee.ID, *got.AcceptedByID)
	require.True(t, at.Equal(*got.AcceptedAt))
	_, err = repos.GetInvitationByOrgAndEmail(ctx, o.ID, "invitee@example.com")
	require.True(t, pluginkit.IsNotFound(err), "%v", err)
	n, err = repos.CountPendingInvitationsByOrgID(ctx, o.ID)
	require.NoError(t, err)
	require.Zero(t, n)

	// Step 5: list by organization with the inviter, newest first
	list, total, err := repos.ListInvitationsByOrgID(ctx, o.ID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, "Inviter", list[0].Inviter.Name)

	// Step 6: deletes (by id, every invitation of an inviter)
	require.NoError(t, repos.DeleteInvitationByID(ctx, expired.ID))
	cleaner, ok := repos.IInvitationRepo.(orgrepo.IInviterInvitationsCleaner)
	require.True(t, ok)
	require.NoError(t, cleaner.DeleteInvitationsByInviterID(ctx, inviter.ID))
	_, total, err = repos.ListInvitationsByOrgID(ctx, o.ID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.Zero(t, total)
}

func testTeams(t *testing.T, env Env) {
	ctx := context.Background()
	repos := orgRepos(t, env)
	alice := user(t, env, "alice@example.com", "Alice")
	bob := user(t, env, "bob@example.com", "Bob")
	o := org(t, repos, "Org", "org", alice.ID, orgmodels.OrgStatusActive)

	// Step 1: teams, newest first
	core1, err := repos.CreateTeam(ctx, &orgmodels.Team{Name: "Core", OrganizationID: o.ID, Base: models.Base{CreatedAt: ms(time.Now().Add(-time.Minute))}})
	require.NoError(t, err)
	web, err := repos.CreateTeam(ctx, &orgmodels.Team{Name: "Web", OrganizationID: o.ID})
	require.NoError(t, err)
	teams, total, err := repos.ListTeamsByOrgID(ctx, o.ID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Equal(t, web.ID, teams[0].ID)
	got, err := repos.UpdateTeam(ctx, core1.ID, map[string]any{"Name": "Platform"})
	require.NoError(t, err)
	require.Equal(t, "Platform", got.Name)
	_, err = repos.GetTeamByID(ctx, "missing")
	require.True(t, pluginkit.IsNotFound(err), "%v", err)

	// Step 2: team members with their user
	for _, tm := range []*orgmodels.TeamMember{{TeamID: core1.ID, UserID: alice.ID}, {TeamID: core1.ID, UserID: bob.ID}, {TeamID: web.ID, UserID: bob.ID}} {
		created, err := repos.CreateTeamMember(ctx, tm)
		require.NoError(t, err)
		require.NotEmpty(t, created.ID)
	}
	tm, err := repos.GetTeamMember(ctx, core1.ID, bob.ID)
	require.NoError(t, err)
	require.Equal(t, bob.ID, tm.UserID)
	members, total, err := repos.ListMembersByTeamID(ctx, core1.ID, orgmodels.Pagination{})
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	for _, m := range members {
		require.NotNil(t, m.User)
	}
	lister, ok := repos.ITeamMemberRepo.(orgrepo.IUserTeamsLister)
	require.True(t, ok)
	bobTeams, err := lister.ListTeamsByUserID(ctx, bob.ID)
	require.NoError(t, err)
	require.Len(t, bobTeams, 2)

	// Step 3: removing members and teams
	require.NoError(t, repos.DeleteTeamMember(ctx, core1.ID, alice.ID))
	_, err = repos.GetTeamMember(ctx, core1.ID, alice.ID)
	require.True(t, pluginkit.IsNotFound(err), "%v", err)
	require.NoError(t, repos.DeleteTeam(ctx, web.ID))
	bobTeams, err = lister.ListTeamsByUserID(ctx, bob.ID)
	require.NoError(t, err)
	require.Len(t, bobTeams, 1, "deleting a team removes its members")
	cleaner, ok := repos.ITeamMemberRepo.(orgrepo.IUserTeamMembersCleaner)
	require.True(t, ok)
	require.NoError(t, cleaner.DeleteTeamMembersByUserID(ctx, bob.ID))
	bobTeams, err = lister.ListTeamsByUserID(ctx, bob.ID)
	require.NoError(t, err)
	require.Empty(t, bobTeams)
}

func testRoles(t *testing.T, env Env) {
	ctx := context.Background()
	repos := orgRepos(t, env)
	o := org(t, repos, "Org", "org", "", orgmodels.OrgStatusActive)
	o2 := org(t, repos, "Other", "other", "", orgmodels.OrgStatusActive)

	// Step 1: create with a permission document and goauth operations
	perm := orgmodels.Permission{"project": {"create", "read"}}
	r, err := repos.CreateRole(ctx, &orgmodels.OrganizationRole{OrganizationID: o.ID, Role: "dev", Permission: perm, Ops: orgmodels.Operations{"deploy"}})
	require.NoError(t, err)
	require.NotEmpty(t, r.ID)
	got, err := repos.GetRole(ctx, o.ID, "dev")
	require.NoError(t, err)
	require.Equal(t, perm, got.Permission)
	require.Equal(t, orgmodels.Operations{"deploy"}, got.Ops)

	// Step 2: role names are unique per organization only
	_, err = repos.CreateRole(ctx, &orgmodels.OrganizationRole{OrganizationID: o.ID, Role: "dev", Permission: orgmodels.Permission{}})
	require.Error(t, err)
	_, err = repos.CreateRole(ctx, &orgmodels.OrganizationRole{OrganizationID: o2.ID, Role: "dev", Permission: orgmodels.Permission{}})
	require.NoError(t, err)
	list, err := repos.ListRolesByOrgID(ctx, o.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)

	// Step 3: updates, rename, delete
	got, err = repos.UpdateRole(ctx, o.ID, "dev", orgmodels.Permission{"project": {"read"}})
	require.NoError(t, err)
	require.Equal(t, []string{"read"}, got.Permission["project"])
	require.Equal(t, orgmodels.Operations{"deploy"}, got.Ops, "UpdateRole keeps the operations")
	got, err = repos.UpdateRoleWithOps(ctx, o.ID, "dev", orgmodels.Permission{"project": {"delete"}}, nil)
	require.NoError(t, err)
	require.Nil(t, got.Ops)
	require.NoError(t, repos.RenameRole(ctx, o.ID, "dev", "developer"))
	_, err = repos.GetRole(ctx, o.ID, "dev")
	require.True(t, pluginkit.IsNotFound(err), "%v", err)
	got, err = repos.GetRole(ctx, o.ID, "developer")
	require.NoError(t, err)
	require.Equal(t, []string{"delete"}, got.Permission["project"])
	require.NoError(t, repos.DeleteRole(ctx, o.ID, "developer"))
	list, err = repos.ListRolesByOrgID(ctx, o.ID)
	require.NoError(t, err)
	require.Empty(t, list)
}

func testDeleteOrganization(t *testing.T, env Env) {
	ctx := context.Background()
	repos := orgRepos(t, env)
	u := user(t, env, "u@example.com", "U")
	o := org(t, repos, "Doomed", "doomed", u.ID, orgmodels.OrgStatusActive)
	keep := org(t, repos, "Keep", "keep", u.ID, orgmodels.OrgStatusActive)
	for _, id := range []string{o.ID, keep.ID} {
		member(t, repos, id, u.ID, orgmodels.OrgRoleOwner)
		_, err := repos.CreateInvitation(ctx, &orgmodels.Invitation{OrganizationID: id, Email: "x@example.com", Role: orgmodels.OrgRoleMember, ExpiresAt: ms(time.Now().Add(time.Hour)), InviterID: u.ID})
		require.NoError(t, err)
		team, err := repos.CreateTeam(ctx, &orgmodels.Team{Name: "T", OrganizationID: id})
		require.NoError(t, err)
		_, err = repos.CreateTeamMember(ctx, &orgmodels.TeamMember{TeamID: team.ID, UserID: u.ID})
		require.NoError(t, err)
		_, err = repos.CreateRole(ctx, &orgmodels.OrganizationRole{OrganizationID: id, Role: "r", Permission: orgmodels.Permission{}})
		require.NoError(t, err)
	}

	// every row of the organization goes, the other organization's rows stay
	require.NoError(t, repos.DeleteOrg(ctx, o.ID))
	_, err := repos.GetOrgByID(ctx, o.ID)
	require.True(t, pluginkit.IsNotFound(err), "%v", err)
	for model, field := range map[string]string{
		orgmodels.ModelMember: "organizationId", orgmodels.ModelInvitation: "organizationId",
		orgmodels.ModelTeam: "organizationId", orgmodels.ModelOrganizationRole: "organizationId",
	} {
		n, err := env.Adapter.Count(ctx, model, []adapter.Where{{Field: field, Value: o.ID}})
		require.NoError(t, err)
		require.Zero(t, n, model)
		n, err = env.Adapter.Count(ctx, model, []adapter.Where{{Field: field, Value: keep.ID}})
		require.NoError(t, err)
		require.EqualValues(t, 1, n, model)
	}
	n, err := env.Adapter.Count(ctx, orgmodels.ModelTeamMember, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}

// ─── admin ───────────────────────────────────────────────────────────────────

func adminRepo(t *testing.T, env Env) *adapteradmin.AdminRepo {
	t.Helper()
	r, err := adapteradmin.New(env.Adapter, env.Schema)
	require.NoError(t, err)
	return r
}

func testAdminUsers(t *testing.T, env Env) {
	ctx := context.Background()
	repo := adminRepo(t, env)
	accounts := core(t, env)

	// Step 1: user + credential account in one go
	u, err := repo.CreateUserWithAccount(ctx, &models.User{UserDto: models.UserDto{Name: "Admin Made", Email: "Made@Example.com", Role: enums.User}}, "hash-1")
	require.NoError(t, err)
	require.NotEmpty(t, u.ID)
	acc, err := accounts.FindAccountByUserAndProvider(ctx, u.ID, models.ProvCredential)
	require.NoError(t, err)
	require.Equal(t, "hash-1", *acc.Password)
	require.Equal(t, u.ID, acc.AccountID)
	_, err = repo.CreateUserWithAccount(ctx, &models.User{UserDto: models.UserDto{Name: "Dup", Email: "made@example.com"}}, "x")
	require.Error(t, err, "emails are unique")

	// Step 2: passwords: replace the hash; create the credential account when missing
	require.NoError(t, repo.SetUserPassword(ctx, u.ID, "hash-2"))
	acc, err = accounts.FindAccountByUserAndProvider(ctx, u.ID, models.ProvCredential)
	require.NoError(t, err)
	require.Equal(t, "hash-2", *acc.Password)
	social := user(t, env, "social@example.com", "Social")
	require.NoError(t, repo.SetUserPassword(ctx, social.ID, "hash-3"))
	acc, err = accounts.FindAccountByUserAndProvider(ctx, social.ID, models.ProvCredential)
	require.NoError(t, err)
	require.Equal(t, "hash-3", *acc.Password)

	// Step 3: role, ban (reason, expiry), unban
	got, err := repo.SetUserRole(ctx, u.ID, enums.Admin)
	require.NoError(t, err)
	require.Equal(t, enums.Admin, got.Role)
	exp := ms(time.Now().Add(time.Hour))
	got, err = repo.BanUser(ctx, u.ID, str("spam"), &exp)
	require.NoError(t, err)
	require.True(t, got.Banned)
	require.Equal(t, "spam", *got.BanReason)
	require.True(t, exp.Equal(*got.BanExpires))
	got, err = repo.UnbanUser(ctx, u.ID)
	require.NoError(t, err)
	require.False(t, got.Banned)
	require.Nil(t, got.BanReason)
	require.Nil(t, got.BanExpires)

	// Step 4: lookups and updates; a missing user is USER_NOT_FOUND
	got, err = repo.GetUserByEmail(ctx, "MADE@example.com")
	require.NoError(t, err)
	require.Equal(t, u.ID, got.ID)
	got, err = repo.UpdateUser(ctx, u.ID, map[string]any{"Name": "Renamed", "emailVerified": true})
	require.NoError(t, err)
	require.Equal(t, "Renamed", got.Name)
	require.True(t, got.EmailVerified)
	for _, call := range []func() (*models.User, error){
		func() (*models.User, error) { return repo.GetUserByID(ctx, "missing") },
		func() (*models.User, error) { return repo.GetUserByEmail(ctx, "missing@example.com") },
		func() (*models.User, error) { return repo.SetUserRole(ctx, "missing", enums.Admin) },
		func() (*models.User, error) { return repo.BanUser(ctx, "missing", nil, nil) },
		func() (*models.User, error) { return repo.UpdateUser(ctx, "missing", map[string]any{"Name": "x"}) },
	} {
		u, err := call()
		require.ErrorIs(t, err, autherr.ErrUserNotFound)
		require.Nil(t, u)
	}
}

func testAdminListUsers(t *testing.T, env Env) {
	ctx := context.Background()
	repo := adminRepo(t, env)
	names := []string{"Charlie Brown", "Alice Smith", "Bob Stone", "Dora Explorer"}
	for i, n := range names {
		u := user(t, env, fmt.Sprintf("%s@%s.com", strings.ToLower(strings.Fields(n)[0]), []string{"acme", "acme", "beta", "beta"}[i]), n)
		if i%2 == 0 {
			_, err := repo.SetUserRole(ctx, u.ID, enums.Admin)
			require.NoError(t, err)
		}
		if i == 3 {
			_, err := repo.BanUser(ctx, u.ID, nil, nil)
			require.NoError(t, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	p := func(s string) *string { return &s }
	n := func(i int) *int { return &i }
	list := func(in dtos.AdminListUsersInput) ([]string, int64) {
		t.Helper()
		users, total, err := repo.ListUsers(ctx, in)
		require.NoError(t, err)
		out := make([]string, len(users))
		for i, u := range users {
			out[i] = u.Name
		}
		return out, total
	}

	// Step 1: default: newest first, everything
	got, total := list(dtos.AdminListUsersInput{})
	require.EqualValues(t, 4, total)
	require.Equal(t, "Dora Explorer", got[0])
	// Step 2: search across name and email (case-insensitive), or one field
	got, total = list(dtos.AdminListUsersInput{SearchValue: p("ACME")})
	require.EqualValues(t, 2, total)
	got, _ = list(dtos.AdminListUsersInput{SearchValue: p("st"), SearchField: p("name"), SortBy: p("name"), SortDirection: p("asc")})
	require.Equal(t, []string{"Bob Stone"}, got)
	// Step 3: filters: eq on role, banned as a boolean, contains on email
	_, total = list(dtos.AdminListUsersInput{FilterField: p("role"), FilterValue: p("admin")})
	require.EqualValues(t, 2, total)
	got, _ = list(dtos.AdminListUsersInput{FilterField: p("banned"), FilterValue: p("true")})
	require.Equal(t, []string{"Dora Explorer"}, got)
	_, total = list(dtos.AdminListUsersInput{FilterField: p("email"), FilterOperator: p("contains"), FilterValue: p("BETA")})
	require.EqualValues(t, 2, total)
	_, total = list(dtos.AdminListUsersInput{FilterField: p("role"), FilterOperator: p("ne"), FilterValue: p("admin")})
	require.EqualValues(t, 2, total)
	// Step 4: sort and pages
	got, total = list(dtos.AdminListUsersInput{SortBy: p("name"), SortDirection: p("asc"), Limit: n(2), Offset: n(1)})
	require.EqualValues(t, 4, total)
	require.Equal(t, []string{"Bob Stone", "Charlie Brown"}, got)
}

func testAdminSessions(t *testing.T, env Env) {
	ctx := context.Background()
	repo := adminRepo(t, env)
	sessions := core(t, env)
	u := user(t, env, "s@example.com", "S")
	admin := user(t, env, "a@example.com", "A")

	// Step 1: two live sessions (one impersonating) and an expired one
	mk := func(token string, expires time.Time, impersonatedBy *string) *models.Session {
		t.Helper()
		s, err := repo.CreateImpersonationSession(ctx, &models.Session{Token: token, UserID: u.ID, ExpiresAt: ms(expires), ImpersonatedBy: impersonatedBy})
		require.NoError(t, err)
		require.NotEmpty(t, s.ID)
		time.Sleep(2 * time.Millisecond)
		return s
	}
	old := mk("tok-old", time.Now().Add(-time.Hour), nil)
	first := mk("tok-1", time.Now().Add(time.Hour), nil)
	imp := mk("tok-imp", time.Now().Add(time.Hour), &admin.ID)

	// Step 2: list (unexpired, newest first) and get with the user
	list, err := repo.ListUserSessions(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, imp.ID, list[0].ID)
	require.Equal(t, admin.ID, *list[0].ImpersonatedBy)
	got, err := repo.GetSessionByID(ctx, first.ID)
	require.NoError(t, err)
	require.Equal(t, "tok-1", got.Token)
	require.NotNil(t, got.User)
	require.Equal(t, "s@example.com", got.User.Email)
	_, err = repo.GetSessionByID(ctx, "missing")
	require.ErrorIs(t, err, autherr.ErrSessionNotFound)

	// Step 3: revoke by id, by token, all
	require.NoError(t, repo.RevokeUserSession(ctx, first.ID, ""))
	require.NoError(t, repo.RevokeUserSession(ctx, "", "tok-imp"))
	require.Error(t, repo.RevokeUserSession(ctx, "", ""))
	list, err = repo.ListUserSessions(ctx, u.ID)
	require.NoError(t, err)
	require.Empty(t, list)
	require.NoError(t, repo.DeleteSessionByID(ctx, old.ID))
	mk("tok-2", time.Now().Add(time.Hour), nil)
	require.NoError(t, repo.RevokeUserSessions(ctx, u.ID))
	all, err := sessions.ListSessions(ctx, u.ID)
	require.NoError(t, err)
	require.Empty(t, all)
}

func testAdminRemoveUser(t *testing.T, env Env) {
	ctx := context.Background()
	repo := adminRepo(t, env)
	c := core(t, env)
	setup := func(email string) *models.User {
		t.Helper()
		u, err := repo.CreateUserWithAccount(ctx, &models.User{UserDto: models.UserDto{Name: "R", Email: email}}, "hash")
		require.NoError(t, err)
		_, err = repo.CreateImpersonationSession(ctx, &models.Session{Token: "tok-" + email, UserID: u.ID, ExpiresAt: ms(time.Now().Add(time.Hour))})
		require.NoError(t, err)
		return u
	}

	// Step 1: hard delete: user, sessions and accounts are gone
	hard := setup("hard@example.com")
	require.NoError(t, repo.RemoveUser(ctx, hard.ID, false))
	n, err := env.Adapter.Count(ctx, schema.ModelUser, []adapter.Where{{Field: "id", Value: hard.ID}})
	require.NoError(t, err)
	require.Zero(t, n)

	// Step 2: soft delete: the row stays as a tombstone, sessions and accounts are gone, the email is free
	soft := setup("soft@example.com")
	require.NoError(t, repo.RemoveUser(ctx, soft.ID, true))
	n, err = env.Adapter.Count(ctx, schema.ModelUser, []adapter.Where{{Field: "id", Value: soft.ID}})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	_, err = repo.GetUserByID(ctx, soft.ID)
	require.ErrorIs(t, err, autherr.ErrUserNotFound)
	_, err = repo.CreateUserWithAccount(ctx, &models.User{UserDto: models.UserDto{Name: "Again", Email: "soft@example.com"}}, "hash")
	require.NoError(t, err)

	for _, id := range []string{hard.ID, soft.ID} {
		s, err := c.ListSessions(ctx, id)
		require.NoError(t, err)
		require.Empty(t, s)
		a, err := c.FindAccounts(ctx, id)
		require.NoError(t, err)
		require.Empty(t, a)
	}
}
