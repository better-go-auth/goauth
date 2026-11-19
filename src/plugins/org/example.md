# Organization plugin

Organizations, members, invitations, teams and role-based access control. It is the Go version of
better-auth's `organization()` plugin and is compatible with the better-auth `organizationClient()`
plugin.

Runnable example: [src/example/org](../../example/org/main.go)

```sh
go run ./src/example/org     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/org    # the flow below, end to end
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
)

orgPlugin, err := org.NewWithGorm(db, orgconfig.OrgConfig{
	Teams: &orgconfig.TeamsConfig{Enabled: true}, // optional
	InvitaionConfig: orgconfig.InvitaionConfig{
		SendInvitationEmail: func(ctx context.Context, in orgconfig.SendInvitationInput) error {
			// email a link containing in.ID; the invitee calls /organization/accept-invitation with it
			return mailer.Send(in.Email, "https://app.example.com/accept-invitation/"+in.ID)
		},
	},
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "http://localhost:8080"},
	Plugins:    []plugin.Plugin{orgPlugin},
})
```

The plugin adds the `organization`, `member`, `invitation`, `team`, `teamMember` and `organizationRole`
tables, plus `activeOrganizationId` (and `activeTeamId` when teams are on) to the session. The
migration runs during `SetupGoAuth`.

## Options

| Field | Default | Meaning |
|---|---|---|
| `AccessControl` | better-auth `defaultAc` | The statements (resource → actions) roles can use |
| `AccessRoles` | owner / admin / member | Predefined roles. Setting this replaces the defaults |
| `DynamicAccessControl` | off | `{Enabled: true}` lets organizations create roles in the database |
| `Teams` | off | `{Enabled: true}` turns the team endpoints on. A default team is created with each organization |
| `CreatorRole` | `owner` | Role given to the user who creates an organization |
| `OrgNeedsApproval` | false | New organizations stay `pending` until a system admin approves them |
| `AllowUserToCreateOrganization` / `OrganizationLimit` | allowed / unlimited | Who may create organizations, and how many |
| `MembershipLimit` / `InvitationLimit` | 100 / 100 | Per-organization limits |
| `InvitationExpiresIn` | 48h | Invitation lifetime |
| `SendInvitationEmail` | none | Called with the invitation (ID, email, role, organization, inviter) |
| `OrganizationHooks` | none | before/after hooks for organizations, members, invitations, teams |
| `GoAuth.LegacyPermissions` | false | goauth's old permission rules (see below) |

## How authorization works

Every organization member has a **role** in that organization (`member.role`, stored per
organization, not on the user). A role is a set of `resource: [actions]` statements, as in better-auth's
access control. A member may hold several comma-separated roles (`"admin,billing"`). One of them must
grant the whole request.

### Default roles

With no options, the better-auth defaults apply:

| Resource | Actions | owner | admin | member |
|---|---|---|---|---|
| `organization` | `update`, `delete` | all | `update` | – |
| `member` | `create`, `update`, `delete` | all | all | – |
| `invitation` | `create`, `cancel` | all | all | – |
| `team` | `create`, `update`, `delete` | all | all | – |
| `ac` | `create`, `read`, `update`, `delete` | all | all | `read` |

goauth's own endpoints check these permissions. For example, `invite-member` needs
`invitation:create`, `update-member-role` needs `member:update`, `delete` needs
`organization:delete`, and `create-team` needs `team:create`. Reading endpoints (`list-members`,
`get-full-organization`) only require membership.

### Custom resources and roles

Add your own resources by extending the default statements. Then redefine the roles that should have
them. This is better-auth's `createAccessControl` / `ac.newRole` (package
`src/providers/access`):

```go
projectActions := []string{"create", "read", "delete"}
ac := access.NewAccessControl(orgconfig.DefaultStatements.Merge(access.Statements{
	"project": projectActions,
}))

orgconfig.OrgConfig{
	AccessControl: ac,
	AccessRoles: map[string]access.Role{
		"owner":  ac.NewRole(orgconfig.OwnerAC.Statements().Merge(access.Statements{"project": projectActions})),
		"admin":  ac.NewRole(orgconfig.AdminAC.Statements().Merge(access.Statements{"project": {"create", "read"}})),
		"member": ac.NewRole(orgconfig.MemberAC.Statements().Merge(access.Statements{"project": {"read"}})),
	},
}
```

`AccessRoles` replaces the defaults, so list every role you use. Start from `OwnerAC` / `AdminAC` /
`MemberAC` to keep the built-in endpoints working. You can also pass them as options:
`org.WithAccessControl(ac)` and `org.WithRoles(roles)`.

### Dynamic roles (per organization, in the database)

With `DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{Enabled: true}`, members holding
the `ac:*` permissions can manage roles through `/organization/create-role`, `update-role`,
`delete-role`, `list-roles` and `get-role`:

```json
POST /api/auth/organization/create-role
{ "role": "editor", "permission": { "project": ["read", "create"] } }
```

- A resource that is not in `AccessControl` is rejected with `INVALID_RESOURCE`.
- You cannot grant a permission you don't have yourself.
- A database role with the same name as a predefined role is **merged** into the predefined role.
- Predefined roles cannot be deleted. A role still assigned to members cannot be deleted either.
- Roles are cached in memory and in secondary storage (`CacheRoles`, `CacheTTL`).

### Checking a permission from the client

`POST /api/auth/organization/has-permission` checks the caller's role in the active organization, or
in `organizationId` if the body sets it:

```json
{ "permissions": { "project": ["create"] } }   →   { "error": null, "success": false }
```

This endpoint reads the role from the member table, so a role change takes effect immediately.

### Protecting your own routes

The plugin returns middlewares that authorize a route by the caller's organization role. Put goauth's
`Authenticate` middleware before them:

```go
huma.Register(api, huma.Operation{
	Method: http.MethodPost, Path: "/api/example/projects",
	Middlewares: huma.Middlewares{
		auth.MiddlewareInt().Authenticate(),          // 401 without a session
		orgPlugin.RequirePermission("project", "create"), // 403 unless the role grants project:create
	},
}, handler)
```

| Middleware | Checks |
|---|---|
| `RequirePermission(resource, action)` | The role grants `resource:action` |
| `RequireOperation(opID)` | A dynamic role lists `opID` in its `ops` (goauth extension) |
| `Authorize(middleware.AuthOptions{...})` | Either or both, according to `Method` (`permission`, `ops`, `both`) |
| `HTTPRequirePermission`, `HTTPRequireOperation`, `HTTPAuthorize` | The same checks as `net/http` middlewares |

The middleware uses the session's active organization. If the session has none, it uses the
`X-Organization-Id` header. Without either, it returns 403. Inside the handler,
`authenticator.SessionFromContext(ctx).Session.ActiveOrganizationID` gives the organization.

`RequirePermission` reads the caller's role from the member table on every request (one query), like
better-auth's `hasPermission`. A role change (`update-member-role`) or removal (`remove-member`) applies
on the member's next request; the role cached on the session at `set-active` is not trusted.

The owner is checked like any other role: it only has the statements `OwnerAC` (or your `owner` role)
grants. A route needing an action no role lists is forbidden for the owner too, matching
`has-permission`. (Operation checks with `RequireOperation`, a goauth-only feature, still let the owner
through.)

### Legacy goauth rules

Set `GoAuth.LegacyPermissions: true`, or set the legacy `Roles` map, to switch to goauth's earlier
rules: the owner bypasses every check, admin may do everything except `organization:delete`, member
may only `read`/`list`/`get`, and `Roles` may use `"*"` wildcards. These rules are ignored when
`AccessControl` or `AccessRoles` is set.

### System admins and organization approval

The system user role (`user.role`, set by the admin plugin; the column only exists when the admin plugin is
installed) is separate from organization roles. It
is used only for the `/admin/organization/*` endpoints (`create`, `get`, `list`, `approve`, `block`,
`unblock`). These endpoints require the user role to include `admin`, whatever the admin plugin's
access control says. With `OrgNeedsApproval: true`, a new organization is `pending`. It cannot become
active or invite members until a system admin calls:

```json
POST /api/auth/admin/organization/approve
{ "organizationId": "..." }
```

## Endpoints (under `/api/auth/organization`)

Every route answers like better-auth 1.6 (status 200, same JSON, same error codes), so the official
`organizationClient()` works unchanged. Responses carry no Huma `$schema` field.

| Method | Path | Body / query | Permission | Response |
|---|---|---|---|---|
| POST | `/create` | `name`, `slug`, `logo?`, `metadata?` (object), `keepCurrentActiveOrganization?` | any user. Becomes the active organization | organization + `members: [creator]` |
| POST | `/check-slug` | `slug` | any user | `{status: true}`, or 400 `ORGANIZATION_SLUG_ALREADY_TAKEN` |
| POST | `/set-active` | `organizationId` or `organizationSlug` (`organizationId: null` unsets) | member | the organization, or `null` |
| GET | `/get-full-organization` | `?organizationId` / `?organizationSlug` / `?membersLimit` (default: the active organization) | member | organization + `members` (with `user`), `invitations`, `teams` (teams enabled); `null` when no organization is selected |
| GET | `/list` | – | the caller's organizations | array |
| POST | `/update` | `organizationId?`, `data: {name, slug, logo, metadata}` | `organization:update` | organization |
| POST | `/delete` | `organizationId` | `organization:delete` | the deleted organization |
| POST | `/invite-member` | `email`, `role` (string or array), `organizationId?`, `teamId?` | `invitation:create`; only owners may invite owners | invitation |
| POST | `/accept-invitation` | `invitationId` | the invited email. Makes the organization active | `{invitation, member}` |
| POST | `/reject-invitation` | `invitationId` | the invited email | `{invitation, member: null}` |
| POST | `/cancel-invitation` | `invitationId` | `invitation:cancel` | invitation |
| GET | `/get-invitation` | `?id` | the invited email (pending invitations only) | invitation + `organizationName`, `organizationSlug`, `inviterEmail` |
| GET | `/list-invitations` | `?organizationId` | member | array |
| GET | `/list-user-invitations` | – | caller with a verified email | array of pending invitations + `organizationName` (goauth also adds `organizationSlug`, `inviter`) |
| GET | `/get-active-member` | – | member of the active organization | member + `user: {id, name, email, image}` |
| GET | `/get-active-member-role` | `?userId`, `?organizationId`, `?organizationSlug` | member | `{role}` |
| GET | `/list-members` | `?organizationId` / `?organizationSlug`, `?limit`, `?offset`, `?sortBy`, `?sortDirection` | member | `{members, total}` |
| POST | `/update-member-role` | `memberId`, `role` (string or array), `organizationId?` | `member:update`; only owners change owners | member |
| POST | `/remove-member` | `memberIdOrEmail`, `organizationId?` | `member:delete` (401 when missing); owners only by owners, never the last one | `{member}` |
| POST | `/leave` | `organizationId` | member (not the last owner) | member |
| POST | `/has-permission` | `permissions`, `organizationId?` | member | `{error, success}` |
| POST | `/create-role`, `/update-role`, `/delete-role`; GET `/list-roles`, `/get-role` | see above | `ac:*` (dynamic access control) | |
| POST | `/create-team`, `/update-team` | `name` / `teamId`, `data` | `team:create` / `team:update` (teams enabled) | team |
| POST | `/remove-team` | `teamId` | `team:delete`; not the caller's active team | `{message: "Team removed successfully."}` |
| POST | `/add-team-member` | `teamId`, `userId` | `member:update`. Adding twice returns the existing membership | team member |
| POST | `/remove-team-member` | `teamId`, `userId` | `member:delete` | `{message: "Team member removed successfully."}` |
| POST | `/set-active-team` | `teamId` (`null` unsets; omitted = the active team) | team member; team of the active organization | the team, or `null` |
| GET | `/list-teams` | `?organizationId` | member | array |
| GET | `/list-team-members` | `?teamId` (default: the active team) | team member | array (goauth adds `user`) |
| GET | `/list-user-teams` | – | any user | the caller's teams in organizations they belong to |

### goauth-only routes

These paths do not exist in better-auth; official clients never call them:

| Method | Path | Purpose |
|---|---|---|
| GET | `/organization/get-member` | a member (`?userId`, default the caller) of `?organizationId` |
| DELETE | `/organization/delete` | alias of `POST /organization/delete` |
| POST/GET | `/organization/team/create`, `/team/update`, `/team/delete`, `/team/list`, `/team/add-member`, `/team/remove-member`, `/team/list-members` | older aliases of the better-auth team routes |
| POST/GET | `/admin/organization/create`, `/get`, `/list`, `/approve`, `/block`, `/unblock` | system-admin organization management and the approval workflow |

## Flow

```sh
H='-H Origin:http://localhost:8080 -H Content-Type:application/json'

# 1. the owner signs up and creates an organization (it becomes the active one)
curl -c owner $H -d '{"email":"owner@example.com","password":"Password123!","name":"Olivia"}' \
  http://localhost:8080/api/auth/sign-up/email
curl -b owner $H -d '{"name":"Acme","slug":"acme"}' http://localhost:8080/api/auth/organization/create

# 2. invite Bob as a member (the invitation ID is printed in the server log by the example sender)
curl -b owner $H -d '{"email":"bob@example.com","role":"member"}' \
  http://localhost:8080/api/auth/organization/invite-member

# 3. Bob signs up and accepts (accepting already makes the organization active; set-active switches later)
curl -c bob $H -d '{"email":"bob@example.com","password":"Password123!","name":"Bob"}' \
  http://localhost:8080/api/auth/sign-up/email
curl -b bob $H -d '{"invitationId":"<id>"}' http://localhost:8080/api/auth/organization/accept-invitation
curl -b bob $H -d '{"organizationId":"<org id>"}' http://localhost:8080/api/auth/organization/set-active

# 4. as member Bob may read projects (200) but not create them (403 FORBIDDEN)
curl -b bob http://localhost:8080/api/example/projects
curl -b bob $H -d '{"name":"Gemini"}' http://localhost:8080/api/example/projects

# 5. the owner promotes Bob to admin; now he can create projects but not delete them
curl -b owner $H -d '{"memberId":"<bob member id>","role":"admin"}' \
  http://localhost:8080/api/auth/organization/update-member-role
```

The test (`main_test.go`) runs this whole flow and also checks `has-permission`, invitations by members
and admins, teams, and that demoting or removing a member takes effect on the next request.

## Errors

Codes, messages and statuses are better-auth's `ORGANIZATION_ERROR_CODES`, per route:

| Code | When |
|---|---|
| `UNAUTHORIZED` (401) | No session |
| `NO_ACTIVE_ORGANIZATION` (400) | No `organizationId` and no active organization (member, team and role routes, `has-permission`, `get-active-member`) |
| `ORGANIZATION_NOT_FOUND` (400) | Unknown organization or slug |
| `USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION` | Non-member on `update`/`delete`/`add-team-member` (400), `set-active`/`get-full-organization` (403), `has-permission` (401) |
| `YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION` (403) | Non-member on `list-members`, `get-active-member-role` |
| `MEMBER_NOT_FOUND` (400) | Non-member on `invite-member`, `update-member-role`, `remove-member`, `leave`, `get-active-member`; unknown member |
| `YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION` / `..._DELETE_THIS_ORGANIZATION` / `..._INVITE_USERS_TO_THIS_ORGANIZATION` / `..._CANCEL_THIS_INVITATION` / `..._UPDATE_THIS_MEMBER` (403) | Missing permission on the route |
| `YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER` (401) | `remove-member` without `member:delete` |
| `YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE` (403) | A non-owner invites an owner |
| `YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER` / `..._WITHOUT_AN_OWNER` (400) | Removing, demoting or leaving as the last owner |
| `ORGANIZATION_ALREADY_EXISTS` / `ORGANIZATION_SLUG_ALREADY_TAKEN` (400) | Slug used (`create` / `check-slug`, `update`) |
| `YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION` / `YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS` (403) | `AllowUserToCreateOrganization` / `OrganizationLimit` |
| `ORGANIZATION_MEMBERSHIP_LIMIT_REACHED` / `INVITATION_LIMIT_REACHED` (403) | `MembershipLimit` / `InvitationLimit` |
| `ORGANIZATION_DELETION_DISABLED` (404) | `DisableOrganizationDeletion` |
| `INVITATION_NOT_FOUND` (400) | Unknown, used or expired invitation |
| `YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION` (403) | Someone else's invitation |
| `USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION` / `USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION` (400) | Re-invite (without `CancelPendingInvitationsOnReInvite`) / invite a member |
| `EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION` / `EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION` (403) | Unverified email (`RequireEmailVerificationOnInvitation`, `list-user-invitations`) |
| `TEAM_NOT_FOUND`, `USER_IS_NOT_A_MEMBER_OF_THE_TEAM`, `YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM`, `UNABLE_TO_REMOVE_LAST_TEAM` (400); `TEAM_MEMBER_LIMIT_REACHED` (403); `YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS` (400) | Team routes |
| `ORGANIZATION_PENDING_APPROVAL` / `ORGANIZATION_SUSPENDED` / `ORGANIZATION_NOT_ACTIVE` (403) | goauth's approval workflow: the organization is not active (set-active, invite-member) |
| `INVALID_RESOURCE` | A dynamic role uses a resource that is not in `AccessControl` |
| `YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE` (and update/delete/read/list) | Missing `ac:*` permission |
| `CANNOT_DELETE_A_PRE_DEFINED_ROLE` / `ROLE_IS_ASSIGNED_TO_MEMBERS` | Role deletion refused |
| `FORBIDDEN` (403) | `RequirePermission` on your own routes, and goauth-only routes |
