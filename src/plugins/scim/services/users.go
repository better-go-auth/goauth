package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/app/services/userdelete"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/plugins/scim/config"
	scimdtos "github.com/better-go-auth/goauth/src/plugins/scim/dtos"
)

// findManyLimit is better-auth's default findMany limit (the user list endpoint does not paginate).
const findManyLimit = 100

// isoMillis formats dates like JavaScript's Date.toJSON().
const isoMillis = "2006-01-02T15:04:05.000Z"

// ─── mappings ────────────────────────────────────────────────────────────────

// accountID is better-auth's getAccountId: externalId, else userName.
func accountID(in *scimdtos.SCIMUserInput) string {
	if in.ExternalID != nil {
		return *in.ExternalID
	}
	return in.UserName
}

// formattedName is better-auth's getFormattedName.
func formattedName(given, family string) string {
	switch {
	case given != "" && family != "":
		return given + " " + family
	case given != "":
		return given
	}
	return family
}

// fullName is better-auth's getUserFullName: formatted, else given + family, else the email.
func fullName(email string, name *scimdtos.SCIMName) string {
	if name == nil {
		return email
	}
	if f := strings.TrimSpace(name.Formatted); f != "" {
		return f
	}
	if n := formattedName(name.GivenName, name.FamilyName); n != "" {
		return n
	}
	return email
}

// primaryEmail is better-auth's getUserPrimaryEmail: the primary email, else the first, else userName.
func primaryEmail(in *scimdtos.SCIMUserInput) string {
	for _, e := range in.Emails {
		if e.Primary != nil && *e.Primary {
			return e.Value
		}
	}
	if len(in.Emails) > 0 {
		return in.Emails[0].Value
	}
	return in.UserName
}

// userResource is better-auth's createUserResource.
func userResource(baseURL string, u *models.User, accountID string) scimdtos.SCIMUserResource {
	primary := true
	return scimdtos.SCIMUserResource{
		ID:         u.ID,
		ExternalID: accountID,
		Meta: scimdtos.SCIMMeta{
			ResourceType: "User",
			Created:      u.CreatedAt.UTC().Format(isoMillis),
			LastModified: u.UpdatedAt.UTC().Format(isoMillis),
			Location:     resourceURL("/scim/v2/Users/"+u.ID, baseURL),
		},
		UserName:    u.Email,
		Name:        scimdtos.SCIMName{Formatted: u.Name},
		DisplayName: u.Name,
		Active:      true,
		Emails:      []scimdtos.SCIMEmail{{Primary: &primary, Value: u.Email}},
		Schemas:     []string{UserSchemaID},
	}
}

// userFromRecord converts an adapter user record.
func userFromRecord(r adapter.Record) *models.User {
	u := &models.User{UserDto: models.UserDto{Name: str(r["name"]), Email: str(r["email"])}}
	u.ID = str(r["id"])
	if t, ok := r["createdAt"].(time.Time); ok {
		u.CreatedAt = t
	}
	if t, ok := r["updatedAt"].(time.Time); ok {
		u.UpdatedAt = t
	}
	return u
}

// ─── lookups ─────────────────────────────────────────────────────────────────

// findUser is better-auth's findUserById: the provider's account of userID, membership of the token's
// organization, then the user.
func (s *Service) findUser(ctx context.Context, p *config.Provider, userID string) (*models.User, adapter.Record, error) {
	// Step 1: the SCIM account of this provider
	acc, err := s.store.FindOne(ctx, "account", []adapter.Where{{Field: "userId", Value: userID}, {Field: "providerId", Value: p.ProviderID}})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("scim: find account: %w", err)
	}
	// Step 2: organization scoping
	if p.OrganizationID != "" {
		orgs := s.orgs()
		if orgs == nil {
			return nil, nil, nil
		}
		m, err := orgs.FindMember(ctx, p.OrganizationID, userID)
		if err != nil {
			return nil, nil, fmt.Errorf("scim: find member: %w", err)
		}
		if m == nil {
			return nil, nil, nil
		}
	}
	// Step 3: the user
	u, err := pluginkit.AcceptNotFound(s.kit.Repos.FindUserByID(ctx, userID))
	if err != nil {
		return nil, nil, err
	}
	if u == nil {
		return nil, nil, nil
	}
	return u, acc, nil
}

// canLinkExistingUser is better-auth's canLinkExistingUser.
func (s *Service) canLinkExistingUser(ctx context.Context, p *config.Provider, existing *models.User, email string) (bool, error) {
	policy := s.cfg.LinkExistingUsers
	if policy == nil {
		return false, nil
	}
	if policy.All {
		return true, nil
	}
	// Step 1: at least one constraint must be configured
	if len(policy.TrustedDomains) == 0 && !policy.RequireExistingOrgMembership && policy.ShouldLinkUser == nil {
		return false, nil
	}
	// Step 2: existing membership of the token's organization
	if policy.RequireExistingOrgMembership {
		if p.OrganizationID == "" || s.orgs() == nil {
			return false, nil
		}
		m, err := s.orgs().FindMember(ctx, p.OrganizationID, existing.ID)
		if err != nil {
			return false, err
		}
		if m == nil {
			return false, nil
		}
	}
	// Step 3: trusted domains
	if len(policy.TrustedDomains) > 0 {
		parts := strings.SplitN(email, "@", 2)
		domain := ""
		if len(parts) == 2 {
			domain = strings.ToLower(parts[1])
		}
		ok := false
		for _, d := range policy.TrustedDomains {
			if domain != "" && strings.ToLower(d) == domain {
				ok = true
			}
		}
		if !ok {
			return false, nil
		}
	}
	// Step 4: the custom decision
	if policy.ShouldLinkUser != nil {
		return policy.ShouldLinkUser(ctx, config.LinkUserData{User: existing, Email: email, Provider: config.Provider{ProviderID: p.ProviderID, OrganizationID: p.OrganizationID}})
	}
	return true, nil
}

// ─── endpoints ───────────────────────────────────────────────────────────────

// CreateUser is better-auth's createSCIMUser: a new user (or a linked existing one when allowed) with the
// provider's account and the organization membership.
func (s *Service) CreateUser(ctx context.Context, p *config.Provider, in *scimdtos.SCIMUserInput) (*scimdtos.SCIMUserResource, error) {
	accID := accountID(in)
	// Step 1: the provider's account must not exist yet
	if _, err := s.store.FindOne(ctx, "account", []adapter.Where{{Field: "accountId", Value: accID}, {Field: "providerId", Value: p.ProviderID}}); err == nil {
		return nil, ErrUserExists
	} else if !errors.Is(err, adapter.ErrNotFound) {
		return nil, fmt.Errorf("scim: find account: %w", err)
	}
	email := strings.ToLower(primaryEmail(in))
	name := fullName(email, in.Name)
	existing, err := pluginkit.AcceptNotFound(s.kit.Repos.FindUserByEmail(ctx, email))
	if err != nil {
		return nil, err
	}
	if existing != nil {
		ok, err := s.canLinkExistingUser(ctx, p, existing, email)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrUserExists
		}
	}
	// Step 2: user (unless linked), account and membership in one transaction
	user := existing
	err = s.store.Transaction(ctx, func(ctx context.Context) error {
		if user == nil {
			created, err := s.kit.CreateUser(ctx, &models.User{UserDto: models.UserDto{Email: email, Name: name}})
			if err != nil {
				return err
			}
			user = created
		}
		empty := ""
		if _, err := s.kit.Repos.CreateAccount(ctx, &models.Account{
			UserID: user.ID, ProviderID: models.Providers(p.ProviderID), AccountID: accID, AccessToken: &empty, RefreshToken: &empty,
		}); err != nil {
			return fmt.Errorf("scim: create account: %w", err)
		}
		return s.addMembership(ctx, p, user.ID)
	})
	if err != nil {
		return nil, err
	}
	res := userResource(s.kit.RequestBaseURL(ctx), user, accID)
	return &res, nil
}

// addMembership adds userID to the token's organization as "member" (unless already a member).
func (s *Service) addMembership(ctx context.Context, p *config.Provider, userID string) error {
	if p.OrganizationID == "" || s.orgs() == nil {
		return nil
	}
	m, err := s.orgs().FindMember(ctx, p.OrganizationID, userID)
	if err != nil {
		return err
	}
	if m != nil {
		return nil
	}
	_, err = s.orgs().AddMember(ctx, p.OrganizationID, userID, "member")
	return err
}

// GetUser is better-auth's getSCIMUser.
func (s *Service) GetUser(ctx context.Context, p *config.Provider, userID string) (*scimdtos.SCIMUserResource, error) {
	u, acc, err := s.findUser(ctx, p, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrUserNotFound
	}
	res := userResource(s.kit.RequestBaseURL(ctx), u, str(acc["accountId"]))
	return &res, nil
}

// UpdateUser is better-auth's updateSCIMUser (PUT): email, name and the account id are replaced.
func (s *Service) UpdateUser(ctx context.Context, p *config.Provider, userID string, in *scimdtos.SCIMUserInput) (*scimdtos.SCIMUserResource, error) {
	// Step 1: the provisioned user
	u, acc, err := s.findUser(ctx, p, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrUserNotFound
	}
	// Step 2: user and account together
	accID := accountID(in)
	var updated *models.User
	err = s.store.Transaction(ctx, func(ctx context.Context) error {
		email := strings.ToLower(primaryEmail(in))
		uu, err := s.kit.Repos.UpdateUser(ctx, userID, map[string]interface{}{"Email": email, "Name": fullName(email, in.Name), "UpdatedAt": time.Now().UTC()})
		if err != nil {
			return fmt.Errorf("scim: update user: %w", err)
		}
		if _, err := s.kit.Repos.UpdateAccount(ctx, str(acc["id"]), map[string]interface{}{"AccountID": accID, "UpdatedAt": time.Now().UTC()}); err != nil {
			return fmt.Errorf("scim: update account: %w", err)
		}
		updated = uu
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.kit.RefreshUser(ctx, updated)
	res := userResource(s.kit.RequestBaseURL(ctx), updated, accID)
	return &res, nil
}

// PatchUser is better-auth's patchSCIMUser: add / replace operations on the mapped paths (name, externalId,
// userName); other paths and remove operations are ignored.
func (s *Service) PatchUser(ctx context.Context, p *config.Provider, userID string, ops []scimdtos.SCIMPatchOperation) error {
	// Step 1: the provisioned user
	u, acc, err := s.findUser(ctx, p, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return ErrUserNotFound
	}
	// Step 2: the changes
	userPatch, accountPatch := buildUserPatch(u, ops)
	if len(userPatch) == 0 && len(accountPatch) == 0 {
		return ErrNoValidPatch
	}
	// Step 3: apply them
	if len(userPatch) > 0 {
		update := map[string]interface{}{"UpdatedAt": time.Now().UTC()}
		if v, ok := userPatch["name"]; ok {
			update["Name"] = v
		}
		if v, ok := userPatch["email"]; ok {
			update["Email"] = strings.ToLower(v)
		}
		updated, err := s.kit.Repos.UpdateUser(ctx, userID, update)
		if err != nil {
			return fmt.Errorf("scim: update user: %w", err)
		}
		s.kit.RefreshUser(ctx, updated)
	}
	if v, ok := accountPatch["accountId"]; ok {
		if _, err := s.kit.Repos.UpdateAccount(ctx, str(acc["id"]), map[string]interface{}{"AccountID": v, "UpdatedAt": time.Now().UTC()}); err != nil {
			return fmt.Errorf("scim: update account: %w", err)
		}
	}
	return nil
}

// DeleteUser is better-auth's deleteSCIMUser: an organization token removes the membership and the SCIM
// account; a personal token deletes the user (sessions, plugin rows, accounts, user).
func (s *Service) DeleteUser(ctx context.Context, p *config.Provider, userID string) error {
	// Step 1: the provisioned user
	u, acc, err := s.findUser(ctx, p, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return ErrUserNotFound
	}
	// Step 2: organization deprovisioning
	if p.OrganizationID != "" {
		return s.store.Transaction(ctx, func(ctx context.Context) error {
			if err := s.orgs().RemoveMember(ctx, p.OrganizationID, userID); err != nil {
				return err
			}
			return s.kit.Repos.DeleteAccount(ctx, str(acc["id"]))
		})
	}
	// Step 3: the user itself
	return userdelete.Run(ctx, userdelete.Deps{
		Soft: s.kit.Conf.User.GoAuth.SoftDelete,
		RevokeSessions: func(ctx context.Context, userID string) error {
			return s.kit.Sessions.DeleteUserSessions(ctx, userID)
		},
		RemoveRows: func(ctx context.Context, userID string, soft bool) error {
			return s.kit.InTx(ctx, func(ctx context.Context) error {
				if err := s.kit.Repos.DeleteAccounts(ctx, userID); err != nil {
					return err
				}
				if soft {
					return s.kit.Repos.SoftDeleteUser(ctx, userID)
				}
				return s.kit.Repos.DeleteUser(ctx, userID)
			})
		},
		Hooks: s.kit.Hooks,
	}, userID)
}

// ListUsers is better-auth's listSCIMUsers: the users with an account of the provider (members of the token's
// organization), optionally filtered by `userName eq "..."`. Like better-auth it returns one page (at most 100).
func (s *Service) ListUsers(ctx context.Context, p *config.Provider, filter string) (*scimdtos.SCIMUserList, error) {
	empty := &scimdtos.SCIMUserList{Schemas: []string{ListResponseSchema}, StartIndex: 1, Resources: []scimdtos.SCIMUserResource{}}
	// Step 1: the filter
	filters, err := parseUserFilter(filter)
	if err != nil {
		return nil, err
	}
	// Step 2: the provider's accounts
	accounts, err := s.store.FindMany(ctx, "account", adapter.Query{Where: []adapter.Where{{Field: "providerId", Value: p.ProviderID}}, Limit: findManyLimit})
	if err != nil {
		return nil, fmt.Errorf("scim: list accounts: %w", err)
	}
	if len(accounts) == 0 {
		return empty, nil
	}
	accountOf := map[string]string{}
	ids := make([]string, 0, len(accounts))
	for _, a := range accounts {
		uid := str(a["userId"])
		if _, seen := accountOf[uid]; !seen {
			accountOf[uid] = str(a["accountId"])
			ids = append(ids, uid)
		}
	}
	// Step 3: organization scoping
	if p.OrganizationID != "" {
		orgs := s.orgs()
		var members []string
		for _, id := range ids {
			if orgs == nil {
				break
			}
			m, err := orgs.FindMember(ctx, p.OrganizationID, id)
			if err != nil {
				return nil, fmt.Errorf("scim: find member: %w", err)
			}
			if m != nil {
				members = append(members, id)
			}
		}
		if len(members) == 0 {
			return empty, nil
		}
		ids = members
	}
	// Step 4: the users
	where := append([]adapter.Where{{Field: "id", Op: adapter.In, Value: ids}}, filters...)
	users, err := s.store.FindMany(ctx, "user", adapter.Query{Where: where, Limit: findManyLimit})
	if err != nil {
		return nil, fmt.Errorf("scim: list users: %w", err)
	}
	out := &scimdtos.SCIMUserList{Schemas: []string{ListResponseSchema}, TotalResults: len(users), StartIndex: 1, ItemsPerPage: len(users), Resources: make([]scimdtos.SCIMUserResource, 0, len(users))}
	base := s.kit.RequestBaseURL(ctx)
	for _, r := range users {
		u := userFromRecord(r)
		out.Resources = append(out.Resources, userResource(base, u, accountOf[u.ID]))
	}
	return out, nil
}
