# Admin plugin

User management for administrators: list, create, update, ban and remove users, change roles, manage
sessions and impersonate users. It is the Go version of better-auth's `admin()` plugin, including its
access control (roles made of permissions), and is compatible with the better-auth `adminClient()` plugin.

Runnable example: [src/example/admin](../../example/admin/main.go)

```sh
ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='Password123!' go run ./src/example/admin   # http://localhost:8080/docs
go test ./src/example/admin                                                             # the flow below, end to end
```

## How authorization works

- A **statement** lists every resource and its actions. The admin plugin's are
  `user: create, list, set-role, ban, impersonate, impersonate-admins, delete, set-password, set-email, get, update`
  and `session: list, revoke, delete` (`adminconfig.DefaultStatements`).
- A **role** grants a subset of them. Without custom roles there are two: `admin` (everything except
  `user:impersonate-admins`) and `user` (nothing). New users get `user` (`DefaultRole`).
- A user's `role` can hold several roles, comma separated (`"user,support"`). A permission check
  passes if **any** of them grants **all** the requested actions.
- Each `/admin/*` route checks one permission, for example `list-users` needs `user:list` and
  `ban-user` needs `user:ban`. If the check fails, the route returns 403 with better-auth's error code.
- Users in `AdminUserIDs` pass every check, whatever their role.
- `AdminRoles` (default `["admin"]`) **does not grant permissions**. It only marks which users count
  as admins, so that impersonating them needs `user:impersonate-admins`. To get goauth's old
  behaviour, where every `AdminRoles` entry has full access, use `admin.WithAdminRolesFullAccess(true)`.
  It is ignored when custom roles are set.
- `set-role` keeps the target signed in, like better-auth. Cached sessions are updated, so the new role
  applies on the user's next request.

The organization plugin ([src/plugins/org](../org)) uses the same `access` package for roles
*inside an organization* (`owner`/`admin`/`member`, the member's role in the active organization).
Those roles are separate from `user.role`, which is the one the admin plugin checks.

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/admin"
	adminconfig "github.com/better-go-auth/goauth/src/plugins/admin/config"
	adminrepo "github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"github.com/better-go-auth/goauth/src/providers/access"
)

// the plugin reads and writes users, sessions and accounts through goauth's storage adapter (any database
// GoAuthOptions.Conn points at, or adapter-based Repositories); an empty repository bundle uses that

// default roles (admin / user): nothing to configure
adminPlugin, err := admin.New(adminrepo.AdminRepositories{})

// or custom roles, with an app-specific resource
statements := adminconfig.DefaultStatements.Merge(access.Statements{"report": {"read", "export"}})
ac := access.NewAccessControl(statements)
adminPlugin, err := admin.New(adminrepo.AdminRepositories{},
	admin.WithAccessControl(ac),
	admin.WithRoles(map[string]access.Role{
		"admin":   ac.NewRole(adminconfig.AdminAC.Statements().Merge(access.Statements{"report": {"read", "export"}})),
		"support": ac.NewRole(access.Statements{"user": {"list", "get"}, "report": {"read"}}),
		"user":    ac.NewRole(access.Statements{}),
	}),
)

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn: db, AuthConfig: cfg, Plugins: []plugin.Plugin{adminPlugin},
})
```

Once `WithRoles` is set, only those roles exist. A role missing from the map has no permissions, and
`set-role` rejects it. The plugin adds `role`, `banned`, `banReason` and `banExpires` to the user, and
`impersonatedBy` to the session. These fields appear in every user and session response.

### The first admin

Nobody can call `set-role` until an admin exists. To create the first admin, do one of the following:

- Create the account with the plugin service, as the example does when `ADMIN_EMAIL` is set:
  `adminPlugin.Service().CreateUser(ctx, admindtos.AdminCreateUserInput{Email, Password, Name, Role: "admin"}, "")`.
- Set the user's `role` column to `admin` in the database.
- List the user's ID in `admin.WithAdminUserIDs(id)`.

## Options

| Option | Default | Meaning |
|---|---|---|
| `WithAccessControl(ac)` | `DefaultAC` | All statements (resource → actions) |
| `WithRoles(map[string]access.Role)` | `{admin, user}` | Role → granted statements. When set, only these roles are used |
| `WithAdminUserIDs(ids...)` | none | Users that pass every permission check |
| `WithAdminRoles(roles...)` | `["admin"]` | Roles that count as admins for impersonation. Must exist in `WithRoles` when both are set |
| `WithAllowImpersonatingAdmins(bool)` | false | Impersonate admins without `user:impersonate-admins` |
| `WithDefaultRole(role)` | `user` | Role of new users |
| `WithAdminRolesFullAccess(bool)` | false | goauth only: every `AdminRoles` entry gets the default admin permissions |
| `AdminConfig.ImpersonationSessionExpiresIn` | 7 days | Lifetime of impersonation sessions |

## Endpoints (under `/api/auth/admin`)

| Method | Path | Body / query | Permission |
|---|---|---|---|
| GET / POST | `/list-users` | `limit`, `offset`, `searchField`, `searchValue`, `sortBy`, `filterField`, ... | `user:list` |
| POST | `/create-user` | `email`, `password`, `name`, `role?`, `data?` | `user:create` |
| GET | `/get-user` | `?id=` | `user:get` |
| POST | `/update-user` | `userId`, `data` | `user:update` (+ `set-role`/`ban`/`set-email` for those fields) |
| POST | `/set-role` (`/set-user-role`) | `userId`, `role` | `user:set-role` |
| POST | `/set-user-password` | `userId`, `newPassword` | `user:set-password` |
| POST | `/remove-user` | `userId` | `user:delete` |
| POST | `/ban-user` | `userId`, `banReason?`, `banExpiresIn?` (seconds) | `user:ban` |
| POST | `/unban-user` | `userId` | `user:ban` |
| POST | `/impersonate-user` | `userId` | `user:impersonate` (+ `impersonate-admins` for admins) |
| POST | `/stop-impersonating` | none | an impersonation session |
| POST | `/list-user-sessions` | `userId` | `session:list` |
| POST | `/revoke-user-session` | `sessionToken` or `id` | `session:revoke` |
| POST | `/revoke-user-sessions` | `userId` | `session:revoke` |
| POST | `/has-permission` | `permissions: {resource: [actions]}` | any signed-in user (checks their own role) |

## Flow

```sh
H='-H Origin:http://localhost:8080 -H Content-Type:application/json'
# 1. the seeded admin signs in; alice signs up (role "user")
curl -c admin $H -d '{"email":"admin@example.com","password":"Password123!"}' http://localhost:8080/api/auth/sign-in/email
curl -c alice $H -d '{"email":"alice@example.com","password":"Password123!","name":"Alice"}' http://localhost:8080/api/auth/sign-up/email

# 2. admin lists users; alice gets 403 YOU_ARE_NOT_ALLOWED_TO_LIST_USERS
curl -b admin http://localhost:8080/api/auth/admin/list-users
curl -b alice http://localhost:8080/api/auth/admin/list-users

# 3. admin makes alice "support"; her session stays and her next request has the new role
curl -b admin $H -d '{"userId":"<alice id>","role":"support"}' http://localhost:8080/api/auth/admin/set-role

# 4. alice checks her own permissions and reads the protected reports route
curl -b alice $H -d '{"permissions":{"user":["list"],"report":["read"]}}' http://localhost:8080/api/auth/admin/has-permission
curl -b alice http://localhost:8080/api/example/reports

# 5. admin bans a user (their sessions are revoked, sign-in returns 403 BANNED_USER), then unbans
curl -b admin $H -d '{"userId":"<id>","banReason":"spam","banExpiresIn":86400}' http://localhost:8080/api/auth/admin/ban-user
curl -b admin $H -d '{"userId":"<id>"}' http://localhost:8080/api/auth/admin/unban-user
```

## Protecting your own routes with permissions

Use the same check as the `/admin/*` routes, `Config().HasPermission`, with the user ID and role from
the session:

```go
var permReportRead = access.Req(map[string][]string{"report": {"read"}})

huma.Register(api, huma.Operation{
	Method: http.MethodGet, Path: "/api/example/reports",
	Middlewares: huma.Middlewares{auth.MiddlewareInt().Authenticate()}, // 401 without a session
}, func(ctx context.Context, _ *struct{}) (*Out, error) {
	s, _ := authenticator.SessionFromContext(ctx)
	if !adminPlugin.Config().HasPermission(s.User.ID, s.User.Role, permReportRead) {
		return nil, humatypes.RespondErr(autherr.Err(403, "YOU_ARE_NOT_ALLOWED_TO_READ_REPORTS", "You are not allowed to read reports"))
	}
	...
})
```

`HasPermission` applies the same rules as the plugin: `AdminUserIDs`, comma-separated roles, and the
`DefaultRole` fallback. To get the plugin from the `GoAuth` instance, use
`auth.Plugin(admin.PluginID).(*admin.Plugin)`.

## Errors

| Code | When |
|---|---|
| `YOU_ARE_NOT_ALLOWED_TO_LIST_USERS`, `..._BAN_USERS`, `..._CHANGE_USERS_ROLE`, `..._IMPERSONATE_USERS`, `..._DELETE_USERS`, ... | 403: the caller's role lacks the route's permission |
| `YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE` | 400: `set-role` / `create-user` with a role not in `WithRoles` |
| `YOU_CANNOT_IMPERSONATE_ADMINS` | 403: the target is an admin and the caller lacks `user:impersonate-admins` |
| `BANNED_USER` | 403: a banned user tries to sign in (an expired ban is lifted instead) |

## Notes

- **Impersonation:** `impersonate-user` switches the admin's browser to the impersonation session (the
  session cookie) and keeps the admin's own session in the `admin_session` cookie.
  `stop-impersonating` deletes the impersonation session and restores the admin's session cookie.
- Banning a user revokes all of their sessions. `banExpiresIn` makes the ban temporary.
