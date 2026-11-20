// Package adapterorg implements the organization plugin's repositories on the storage adapter
// (InitContext.Adapter): organization, member, invitation, team, teamMember and organizationRole rows are
// records of the schema registry (models.Schema), so they work on every backend (GORM, memory, ...), in
// either column case and with database-generated ids.
package adapterorg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/recordbind"
	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/common/autherr"
	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/org/models"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository"
	"github.com/better-go-auth/goauth/src/schema"
)

// store is what every repository of the package shares: the adapter, the bindings of the declared models
// and the core repositories used to load the users of members and invitations.
type store struct {
	a          adapter.Adapter
	users      *adapterrepo.Repos
	org        *recordbind.Binding[models.Organization]
	member     *recordbind.Binding[models.Member]
	invitation *recordbind.Binding[models.Invitation]
	team       *recordbind.Binding[models.Team]
	teamMember *recordbind.Binding[models.TeamMember]
	role       *recordbind.Binding[models.OrganizationRole]
}

// base binds the id and timestamps every organization model has.
func base(fields ...recordbind.Field) []recordbind.Field {
	return append([]recordbind.Field{
		{Go: "ID", Name: "id"}, {Go: "CreatedAt", Name: "createdAt"}, {Go: "UpdatedAt", Name: "updatedAt"},
	}, fields...)
}

// newStore binds the organization models to reg. team / teamMember and organizationRole are bound only
// when reg declares them (teams, dynamic access control).
func newStore(a adapter.Adapter, reg *schema.Registry) (*store, error) {
	// Step 1: dependencies
	if a == nil || reg == nil {
		return nil, errors.New("org plugin: a storage adapter and the schema registry are required")
	}
	users, err := adapterrepo.New(a, reg)
	if err != nil {
		return nil, err
	}
	s := &store{a: a, users: users}
	// Step 2: the always present models
	if s.org, err = recordbind.New[models.Organization](reg, models.ModelOrganization, base(
		recordbind.Field{Go: "Name", Name: "name"}, recordbind.Field{Go: "Slug", Name: "slug"},
		recordbind.Field{Go: "Logo", Name: "logo"}, recordbind.Field{Go: "Metadata", Name: "metadata"},
		recordbind.Field{Go: "Status", Name: "status"}, recordbind.Field{Go: "CreatedBy", Name: "createdBy"},
		recordbind.Field{Go: "OrgType", Name: "orgType"},
	)...); err != nil {
		return nil, err
	}
	if s.member, err = recordbind.New[models.Member](reg, models.ModelMember, base(
		recordbind.Field{Go: "OrganizationID", Name: "organizationId"}, recordbind.Field{Go: "UserID", Name: "userId"},
		recordbind.Field{Go: "Role", Name: "role"},
	)...); err != nil {
		return nil, err
	}
	if s.invitation, err = recordbind.New[models.Invitation](reg, models.ModelInvitation, base(
		recordbind.Field{Go: "OrganizationID", Name: "organizationId"}, recordbind.Field{Go: "Email", Name: "email"},
		recordbind.Field{Go: "Role", Name: "role"}, recordbind.Field{Go: "TeamID", Name: "teamId"},
		recordbind.Field{Go: "Status", Name: "status"}, recordbind.Field{Go: "ExpiresAt", Name: "expiresAt"},
		recordbind.Field{Go: "InviterID", Name: "inviterId"}, recordbind.Field{Go: "AcceptedByID", Name: "acceptedById"},
		recordbind.Field{Go: "AcceptedAt", Name: "acceptedAt"},
	)...); err != nil {
		return nil, err
	}
	// Step 3: optional models
	if _, ok := reg.Model(models.ModelTeam); ok {
		if s.team, err = recordbind.New[models.Team](reg, models.ModelTeam, base(
			recordbind.Field{Go: "Name", Name: "name"}, recordbind.Field{Go: "OrganizationID", Name: "organizationId"},
		)...); err != nil {
			return nil, err
		}
		if s.teamMember, err = recordbind.New[models.TeamMember](reg, models.ModelTeamMember, base(
			recordbind.Field{Go: "TeamID", Name: "teamId"}, recordbind.Field{Go: "UserID", Name: "userId"},
		)...); err != nil {
			return nil, err
		}
	}
	if _, ok := reg.Model(models.ModelOrganizationRole); ok {
		if s.role, err = recordbind.New[models.OrganizationRole](reg, models.ModelOrganizationRole, base(
			recordbind.Field{Go: "OrganizationID", Name: "organizationId"}, recordbind.Field{Go: "Role", Name: "role"},
			recordbind.Field{Go: "Permission", Name: "permission", JSON: true},
			recordbind.Field{Go: "Ops", Name: "ops", JSON: true},
		)...); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// NewRepos returns every organization repository on a. reg must contain the organization schema
// (models.Schema); the team repositories are nil without teams and the role repository is nil without
// dynamic access control.
func NewRepos(a adapter.Adapter, reg *schema.Registry) (orgrepo.OrgRepositories, error) {
	s, err := newStore(a, reg)
	if err != nil {
		return orgrepo.OrgRepositories{}, err
	}
	repos := orgrepo.OrgRepositories{
		IOrgRepo:        &OrgRepo{s},
		IMemberRepo:     &MemberRepo{s},
		IInvitationRepo: &InvitationRepo{s},
	}
	if s.team != nil {
		repos.ITeamRepo = &TeamRepo{s}
		repos.ITeamMemberRepo = &TeamMemberRepo{s}
	}
	if s.role != nil {
		repos.IOrganizationRoleRepo = &OrganizationRoleRepo{s}
	}
	return repos, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// notFound is the repositories' "no such row" error (404, what pluginkit.IsNotFound checks).
func notFound(what string) error { return autherr.NotFoundErr("org: " + what + " not found") }

func eq(field string, v any) adapter.Where { return adapter.Where{Field: field, Value: v} }

// create inserts v through b and copies the stored row (generated id, defaults) back into v.
func create[T any](ctx context.Context, s *store, b *recordbind.Binding[T], v *T) (*T, error) {
	rec, err := s.a.Create(ctx, b.Model(), b.Record(v))
	if err != nil {
		return nil, fmt.Errorf("org: create %s: %w", b.Model(), err)
	}
	stored, err := b.Decode(rec)
	if err != nil {
		return nil, err
	}
	*v = *stored
	return v, nil
}

// findOne returns the first match, or the not-found error.
func findOne[T any](ctx context.Context, s *store, b *recordbind.Binding[T], where ...adapter.Where) (*T, error) {
	rec, err := s.a.FindOne(ctx, b.Model(), where)
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, notFound(b.Model())
	}
	if err != nil {
		return nil, fmt.Errorf("org: find %s: %w", b.Model(), err)
	}
	return b.Decode(rec)
}

// findMany returns every match of q.
func findMany[T any](ctx context.Context, s *store, b *recordbind.Binding[T], q adapter.Query) ([]T, error) {
	recs, err := s.a.FindMany(ctx, b.Model(), q)
	if err != nil {
		return nil, fmt.Errorf("org: list %s: %w", b.Model(), err)
	}
	return b.DecodeAll(recs)
}

// page counts the matches of where and returns one page of them.
func page[T any](ctx context.Context, s *store, b *recordbind.Binding[T], where []adapter.Where, sort adapter.SortBy, limit, offset int) ([]T, int64, error) {
	total, err := s.a.Count(ctx, b.Model(), where)
	if err != nil {
		return nil, 0, fmt.Errorf("org: count %s: %w", b.Model(), err)
	}
	rows, err := findMany(ctx, s, b, adapter.Query{
		Where: where, Limit: limit, Offset: offset,
		Sort: []adapter.SortBy{sort, {Field: "id", Desc: sort.Desc}},
	})
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// update applies data (Go field names like "Status", registry names or columns) to the row with id.
func update[T any](ctx context.Context, s *store, b *recordbind.Binding[T], data map[string]any, where ...adapter.Where) error {
	rec, err := b.Updates(data)
	if err != nil {
		return err
	}
	if len(rec) == 0 {
		return nil
	}
	if _, err := s.a.UpdateMany(ctx, b.Model(), where, rec); err != nil {
		return fmt.Errorf("org: update %s: %w", b.Model(), err)
	}
	return nil
}

// deleteWhere removes every match.
func deleteWhere[T any](ctx context.Context, s *store, b *recordbind.Binding[T], where ...adapter.Where) error {
	if _, err := s.a.DeleteMany(ctx, b.Model(), where); err != nil {
		return fmt.Errorf("org: delete %s: %w", b.Model(), err)
	}
	return nil
}

// limitOr returns limit, or def when limit is not positive.
func limitOr(limit, def int) int {
	if limit > 0 {
		return limit
	}
	return def
}

// descending reports whether a sort direction other than "asc" was asked for (goauth's default is desc).
func descending(dir string) bool { return !strings.EqualFold(dir, "asc") }

// usersByID loads the users of ids (a missing user is left out).
func (s *store) usersByID(ctx context.Context, ids []string) (map[string]coremodels.User, error) {
	return s.users.FindUsersByIDs(ctx, ids)
}

// userPtr returns a copy of users[id], or nil.
func userPtr(users map[string]coremodels.User, id string) *coremodels.User {
	if u, ok := users[id]; ok {
		return &u
	}
	return nil
}

// ─── organizations ───────────────────────────────────────────────────────────

// OrgRepo implements orgrepo.IOrgRepo.
type OrgRepo struct{ s *store }

func (r *OrgRepo) CreateOrg(ctx context.Context, org *models.Organization) (*models.Organization, error) {
	return create(ctx, r.s, r.s.org, org)
}

func (r *OrgRepo) GetOrgByID(ctx context.Context, id string) (*models.Organization, error) {
	if id == "" {
		return nil, notFound(models.ModelOrganization)
	}
	return findOne(ctx, r.s, r.s.org, eq("id", id))
}

func (r *OrgRepo) GetOrgBySlug(ctx context.Context, slug string) (*models.Organization, error) {
	if slug == "" {
		return nil, notFound(models.ModelOrganization)
	}
	return findOne(ctx, r.s, r.s.org, eq("slug", slug))
}

func (r *OrgRepo) UpdateOrg(ctx context.Context, id string, data map[string]interface{}) (*models.Organization, error) {
	if err := update(ctx, r.s, r.s.org, data, eq("id", id)); err != nil {
		return nil, err
	}
	return r.GetOrgByID(ctx, id)
}

// DeleteOrg removes the organization with its members, invitations, teams (and their members) and
// dynamic roles in one transaction, so every backend ends up in the same state whether or not it enforces
// the foreign keys.
func (r *OrgRepo) DeleteOrg(ctx context.Context, id string) error {
	s := r.s
	return s.a.Transaction(ctx, func(ctx context.Context) error {
		// Step 1: members and invitations (better-auth's deleteOrganization)
		if err := deleteWhere(ctx, s, s.member, eq("organizationId", id)); err != nil {
			return err
		}
		if err := deleteWhere(ctx, s, s.invitation, eq("organizationId", id)); err != nil {
			return err
		}
		// Step 2: teams and their members
		if s.team != nil {
			teams, err := findMany(ctx, s, s.team, adapter.Query{Where: []adapter.Where{eq("organizationId", id)}, Select: []string{"id"}})
			if err != nil {
				return err
			}
			if len(teams) > 0 {
				ids := make([]string, len(teams))
				for i, t := range teams {
					ids[i] = t.ID
				}
				if err := deleteWhere(ctx, s, s.teamMember, adapter.Where{Field: "teamId", Op: adapter.In, Value: ids}); err != nil {
					return err
				}
			}
			if err := deleteWhere(ctx, s, s.team, eq("organizationId", id)); err != nil {
				return err
			}
		}
		// Step 3: dynamic roles
		if s.role != nil {
			if err := deleteWhere(ctx, s, s.role, eq("organizationId", id)); err != nil {
				return err
			}
		}
		// Step 4: the organization
		return deleteWhere(ctx, s, s.org, eq("id", id))
	})
}

func (r *OrgRepo) ListOrgsByUserID(ctx context.Context, userID string) ([]models.Organization, error) {
	s := r.s
	// Step 1: the user's memberships
	members, err := findMany(ctx, s, s.member, adapter.Query{Where: []adapter.Where{eq("userId", userID)}})
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return []models.Organization{}, nil
	}
	// Step 2: their organizations
	ids := make([]string, len(members))
	for i, m := range members {
		ids[i] = m.OrganizationID
	}
	return findMany(ctx, s, s.org, adapter.Query{
		Where: []adapter.Where{{Field: "id", Op: adapter.In, Value: ids}},
		Sort:  []adapter.SortBy{{Field: "createdAt"}, {Field: "id"}},
	})
}

func (r *OrgRepo) ListAllOrgs(ctx context.Context, status *models.OrgStatus, pagi models.Pagination) ([]models.Organization, int64, error) {
	return r.SearchAllOrgs(ctx, status, "", pagi)
}

// orgSortFields allowlists sortable API names (better-auth names and goauth's old snake_case ones).
var orgSortFields = map[string]string{
	"createdAt": "createdAt", "created_at": "createdAt",
	"updatedAt": "updatedAt", "updated_at": "updatedAt",
	"name": "name", "slug": "slug", "status": "status",
}

func (r *OrgRepo) SearchAllOrgs(ctx context.Context, status *models.OrgStatus, query string, pagi models.Pagination) ([]models.Organization, int64, error) {
	// Step 1: status filter and name/slug search (case-insensitive substring)
	var where []adapter.Where
	if status != nil {
		where = append(where, eq("status", string(*status)))
	}
	if q := strings.TrimSpace(query); q != "" {
		where = append(where,
			adapter.Where{Field: "name", Op: adapter.Contains, Value: q, Insensitive: true, Connector: adapter.Or},
			adapter.Where{Field: "slug", Op: adapter.Contains, Value: q, Insensitive: true, Connector: adapter.Or},
		)
	}
	// Step 2: order and page
	sortBy, ok := orgSortFields[pagi.SortBy]
	if !ok {
		sortBy = "createdAt"
	}
	return page(ctx, r.s, r.s.org, where, adapter.SortBy{Field: sortBy, Desc: descending(pagi.SortDir)}, limitOr(pagi.Limit, 50), pagi.Offset)
}

// ─── members ─────────────────────────────────────────────────────────────────

// MemberRepo implements orgrepo.IMemberRepo. Members are returned with their user.
type MemberRepo struct{ s *store }

// withUsers attaches the users of members.
func (r *MemberRepo) withUsers(ctx context.Context, members []models.Member) error {
	ids := make([]string, len(members))
	for i, m := range members {
		ids[i] = m.UserID
	}
	users, err := r.s.usersByID(ctx, ids)
	if err != nil {
		return err
	}
	for i := range members {
		members[i].User = userPtr(users, members[i].UserID)
	}
	return nil
}

// one loads one member with its user.
func (r *MemberRepo) one(ctx context.Context, where ...adapter.Where) (*models.Member, error) {
	m, err := findOne(ctx, r.s, r.s.member, where...)
	if err != nil {
		return nil, err
	}
	list := []models.Member{*m}
	if err := r.withUsers(ctx, list); err != nil {
		return nil, err
	}
	return &list[0], nil
}

func (r *MemberRepo) CreateMember(ctx context.Context, member *models.Member) (*models.Member, error) {
	return create(ctx, r.s, r.s.member, member)
}

func (r *MemberRepo) GetMemberByOrgAndUser(ctx context.Context, orgID, userID string) (*models.Member, error) {
	return r.one(ctx, eq("organizationId", orgID), eq("userId", userID))
}

func (r *MemberRepo) GetMemberByID(ctx context.Context, id string) (*models.Member, error) {
	return r.one(ctx, eq("id", id))
}

func (r *MemberRepo) UpdateMember(ctx context.Context, id string, data map[string]interface{}) (*models.Member, error) {
	if err := update(ctx, r.s, r.s.member, data, eq("id", id)); err != nil {
		return nil, err
	}
	return r.GetMemberByID(ctx, id)
}

func (r *MemberRepo) DeleteMemberByID(ctx context.Context, id string) error {
	return deleteWhere(ctx, r.s, r.s.member, eq("id", id))
}

func (r *MemberRepo) DeleteMemberByOrgAndUser(ctx context.Context, orgID, userID string) error {
	return deleteWhere(ctx, r.s, r.s.member, eq("organizationId", orgID), eq("userId", userID))
}

// memberSortFields are better-auth's member field names usable as sortBy.
var memberSortFields = map[string]bool{"id": true, "userId": true, "organizationId": true, "role": true, "createdAt": true}

func (r *MemberRepo) ListMembersByOrgID(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Member, int64, error) {
	// Step 1: sortBy uses better-auth's field names; unknown fields and the default sort by createdAt
	// (newest first unless sortDirection is "asc")
	sortBy := pagi.SortBy
	if !memberSortFields[sortBy] {
		sortBy = "createdAt"
	}
	// Step 2: one page with the members' users
	members, total, err := page(ctx, r.s, r.s.member, []adapter.Where{eq("organizationId", orgID)},
		adapter.SortBy{Field: sortBy, Desc: descending(pagi.SortDir)}, limitOr(pagi.Limit, 20), pagi.Offset)
	if err != nil {
		return nil, 0, err
	}
	if err := r.withUsers(ctx, members); err != nil {
		return nil, 0, err
	}
	return members, total, nil
}

// ─── invitations ─────────────────────────────────────────────────────────────

// InvitationRepo implements orgrepo.IInvitationRepo.
type InvitationRepo struct{ s *store }

// withRelations attaches the inviters (and, with orgs, the organizations) of invitations.
func (r *InvitationRepo) withRelations(ctx context.Context, invs []models.Invitation, orgs bool) error {
	// Step 1: inviters
	ids := make([]string, len(invs))
	orgIDs := make([]string, len(invs))
	for i, inv := range invs {
		ids[i] = inv.InviterID
		orgIDs[i] = inv.OrganizationID
	}
	users, err := r.s.usersByID(ctx, ids)
	if err != nil {
		return err
	}
	for i := range invs {
		invs[i].Inviter = userPtr(users, invs[i].InviterID)
	}
	if !orgs || len(invs) == 0 {
		return nil
	}
	// Step 2: organizations
	list, err := findMany(ctx, r.s, r.s.org, adapter.Query{Where: []adapter.Where{{Field: "id", Op: adapter.In, Value: orgIDs}}})
	if err != nil {
		return err
	}
	byID := make(map[string]models.Organization, len(list))
	for _, o := range list {
		byID[o.ID] = o
	}
	for i := range invs {
		if o, ok := byID[invs[i].OrganizationID]; ok {
			invs[i].Organization = &o
		}
	}
	return nil
}

func (r *InvitationRepo) CreateInvitation(ctx context.Context, inv *models.Invitation) (*models.Invitation, error) {
	return create(ctx, r.s, r.s.invitation, inv)
}

func (r *InvitationRepo) GetInvitationByID(ctx context.Context, id string) (*models.Invitation, error) {
	inv, err := findOne(ctx, r.s, r.s.invitation, eq("id", id))
	if err != nil {
		return nil, err
	}
	list := []models.Invitation{*inv}
	if err := r.withRelations(ctx, list, true); err != nil {
		return nil, err
	}
	return &list[0], nil
}

func (r *InvitationRepo) GetInvitationByOrgAndEmail(ctx context.Context, orgID, email string) (*models.Invitation, error) {
	return findOne(ctx, r.s, r.s.invitation,
		eq("organizationId", orgID), eq("status", string(models.InvitationPending)),
		adapter.Where{Field: "email", Value: email, Insensitive: true})
}

func (r *InvitationRepo) UpdateInvitation(ctx context.Context, id string, data map[string]interface{}) (*models.Invitation, error) {
	if err := update(ctx, r.s, r.s.invitation, data, eq("id", id)); err != nil {
		return nil, err
	}
	return r.GetInvitationByID(ctx, id)
}

func (r *InvitationRepo) DeleteInvitationByID(ctx context.Context, id string) error {
	return deleteWhere(ctx, r.s, r.s.invitation, eq("id", id))
}

// DeleteInvitationsByInviterID removes every invitation inviterID sent (user deletion cleanup).
func (r *InvitationRepo) DeleteInvitationsByInviterID(ctx context.Context, inviterID string) error {
	if inviterID == "" {
		return nil
	}
	return deleteWhere(ctx, r.s, r.s.invitation, eq("inviterId", inviterID))
}

func (r *InvitationRepo) ListInvitationsByOrgID(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Invitation, int64, error) {
	invs, total, err := page(ctx, r.s, r.s.invitation, []adapter.Where{eq("organizationId", orgID)},
		adapter.SortBy{Field: "createdAt", Desc: true}, limitOr(pagi.Limit, 20), pagi.Offset)
	if err != nil {
		return nil, 0, err
	}
	if err := r.withRelations(ctx, invs, false); err != nil {
		return nil, 0, err
	}
	return invs, total, nil
}

func (r *InvitationRepo) CountPendingInvitationsByOrgID(ctx context.Context, orgID string) (int64, error) {
	n, err := r.s.a.Count(ctx, models.ModelInvitation, []adapter.Where{eq("organizationId", orgID), eq("status", string(models.InvitationPending))})
	if err != nil {
		return 0, fmt.Errorf("org: count invitations: %w", err)
	}
	return n, nil
}

func (r *InvitationRepo) ListInvitationsByEmail(ctx context.Context, email string) ([]models.Invitation, error) {
	// Step 1: pending, unexpired invitations sent to email (case-insensitive)
	invs, err := findMany(ctx, r.s, r.s.invitation, adapter.Query{
		Where: []adapter.Where{
			eq("status", string(models.InvitationPending)),
			{Field: "email", Value: email, Insensitive: true},
			{Field: "expiresAt", Op: adapter.Gt, Value: coremodels.TimeNow()},
		},
		Sort: []adapter.SortBy{{Field: "createdAt"}, {Field: "id"}},
	})
	if err != nil {
		return nil, err
	}
	// Step 2: with their organizations and inviters
	if err := r.withRelations(ctx, invs, true); err != nil {
		return nil, err
	}
	return invs, nil
}

// ─── teams ───────────────────────────────────────────────────────────────────

// TeamRepo implements orgrepo.ITeamRepo (teams enabled).
type TeamRepo struct{ s *store }

func (r *TeamRepo) CreateTeam(ctx context.Context, team *models.Team) (*models.Team, error) {
	return create(ctx, r.s, r.s.team, team)
}

func (r *TeamRepo) GetTeamByID(ctx context.Context, id string) (*models.Team, error) {
	return findOne(ctx, r.s, r.s.team, eq("id", id))
}

func (r *TeamRepo) ListTeamsByOrgID(ctx context.Context, orgID string, pagi models.Pagination) ([]models.Team, int64, error) {
	return page(ctx, r.s, r.s.team, []adapter.Where{eq("organizationId", orgID)},
		adapter.SortBy{Field: "createdAt", Desc: true}, limitOr(pagi.Limit, 50), pagi.Offset)
}

func (r *TeamRepo) UpdateTeam(ctx context.Context, id string, data map[string]interface{}) (*models.Team, error) {
	if err := update(ctx, r.s, r.s.team, data, eq("id", id)); err != nil {
		return nil, err
	}
	return r.GetTeamByID(ctx, id)
}

func (r *TeamRepo) DeleteTeam(ctx context.Context, id string) error {
	s := r.s
	return s.a.Transaction(ctx, func(ctx context.Context) error {
		// Step 1: the team's members
		if err := deleteWhere(ctx, s, s.teamMember, eq("teamId", id)); err != nil {
			return err
		}
		// Step 2: the team
		return deleteWhere(ctx, s, s.team, eq("id", id))
	})
}

// TeamMemberRepo implements orgrepo.ITeamMemberRepo, IUserTeamsLister and IUserTeamMembersCleaner.
type TeamMemberRepo struct{ s *store }

var (
	_ orgrepo.IUserTeamsLister           = (*TeamMemberRepo)(nil)
	_ orgrepo.IUserTeamMembersCleaner    = (*TeamMemberRepo)(nil)
	_ orgrepo.IInviterInvitationsCleaner = (*InvitationRepo)(nil)
)

func (r *TeamMemberRepo) CreateTeamMember(ctx context.Context, m *models.TeamMember) (*models.TeamMember, error) {
	return create(ctx, r.s, r.s.teamMember, m)
}

func (r *TeamMemberRepo) GetTeamMember(ctx context.Context, teamID, userID string) (*models.TeamMember, error) {
	return findOne(ctx, r.s, r.s.teamMember, eq("teamId", teamID), eq("userId", userID))
}

func (r *TeamMemberRepo) ListMembersByTeamID(ctx context.Context, teamID string, pagi models.Pagination) ([]models.TeamMember, int64, error) {
	// Step 1: one page of the team's members
	out, total, err := page(ctx, r.s, r.s.teamMember, []adapter.Where{eq("teamId", teamID)},
		adapter.SortBy{Field: "createdAt", Desc: true}, limitOr(pagi.Limit, 50), pagi.Offset)
	if err != nil {
		return nil, 0, err
	}
	// Step 2: their users
	ids := make([]string, len(out))
	for i, m := range out {
		ids[i] = m.UserID
	}
	users, err := r.s.usersByID(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range out {
		out[i].User = userPtr(users, out[i].UserID)
	}
	return out, total, nil
}

func (r *TeamMemberRepo) DeleteTeamMember(ctx context.Context, teamID, userID string) error {
	return deleteWhere(ctx, r.s, r.s.teamMember, eq("teamId", teamID), eq("userId", userID))
}

// ListTeamsByUserID returns the teams userID belongs to (better-auth's listTeamsByUser).
func (r *TeamMemberRepo) ListTeamsByUserID(ctx context.Context, userID string) ([]models.Team, error) {
	// Step 1: the user's team memberships
	memberships, err := findMany(ctx, r.s, r.s.teamMember, adapter.Query{Where: []adapter.Where{eq("userId", userID)}})
	if err != nil {
		return nil, err
	}
	if len(memberships) == 0 {
		return []models.Team{}, nil
	}
	// Step 2: their teams (memberships whose team is gone are skipped)
	ids := make([]string, len(memberships))
	for i, m := range memberships {
		ids[i] = m.TeamID
	}
	return findMany(ctx, r.s, r.s.team, adapter.Query{
		Where: []adapter.Where{{Field: "id", Op: adapter.In, Value: ids}},
		Sort:  []adapter.SortBy{{Field: "createdAt"}, {Field: "id"}},
	})
}

// DeleteTeamMembersByUserID removes every team membership of userID (user deletion cleanup).
func (r *TeamMemberRepo) DeleteTeamMembersByUserID(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	return deleteWhere(ctx, r.s, r.s.teamMember, eq("userId", userID))
}

// ─── dynamic roles ───────────────────────────────────────────────────────────

// OrganizationRoleRepo implements orgrepo.IOrganizationRoleRepo (dynamic access control enabled).
type OrganizationRoleRepo struct{ s *store }

func roleWhere(orgID, role string) []adapter.Where {
	return []adapter.Where{eq("organizationId", orgID), eq("role", role)}
}

func (r *OrganizationRoleRepo) CreateRole(ctx context.Context, role *models.OrganizationRole) (*models.OrganizationRole, error) {
	return create(ctx, r.s, r.s.role, role)
}

func (r *OrganizationRoleRepo) GetRole(ctx context.Context, orgID, role string) (*models.OrganizationRole, error) {
	return findOne(ctx, r.s, r.s.role, roleWhere(orgID, role)...)
}

func (r *OrganizationRoleRepo) ListRolesByOrgID(ctx context.Context, orgID string) ([]models.OrganizationRole, error) {
	return findMany(ctx, r.s, r.s.role, adapter.Query{
		Where: []adapter.Where{eq("organizationId", orgID)},
		Sort:  []adapter.SortBy{{Field: "createdAt"}, {Field: "id"}},
	})
}

func (r *OrganizationRoleRepo) UpdateRole(ctx context.Context, orgID, role string, permission models.Permission) (*models.OrganizationRole, error) {
	// Step 1: store the new permission document
	if err := update(ctx, r.s, r.s.role, map[string]any{"permission": permission}, roleWhere(orgID, role)...); err != nil {
		return nil, err
	}
	// Step 2: return the updated role
	return r.GetRole(ctx, orgID, role)
}

func (r *OrganizationRoleRepo) UpdateRoleWithOps(ctx context.Context, orgID, role string, permission models.Permission, ops models.Operations) (*models.OrganizationRole, error) {
	// Step 1: store the new permission and operations documents
	data := map[string]any{"permission": permission, "ops": ops}
	if err := update(ctx, r.s, r.s.role, data, roleWhere(orgID, role)...); err != nil {
		return nil, err
	}
	// Step 2: return the updated role
	return r.GetRole(ctx, orgID, role)
}

func (r *OrganizationRoleRepo) DeleteRole(ctx context.Context, orgID, role string) error {
	return deleteWhere(ctx, r.s, r.s.role, roleWhere(orgID, role)...)
}

// RenameRole changes the name of an organization role.
func (r *OrganizationRoleRepo) RenameRole(ctx context.Context, orgID, oldRole, newRole string) error {
	return update(ctx, r.s, r.s.role, map[string]any{"role": newRole}, roleWhere(orgID, oldRole)...)
}
