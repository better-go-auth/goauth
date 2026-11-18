// Command admin runs goauth with the admin plugin and better-auth style access control: roles are
// sets of permissions (resource -> actions), every /api/auth/admin/* route checks one permission, and
// your own routes can check permissions of their own (here GET /api/example/reports needs report:read).
//
//	ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='Password123!' go run ./src/example/admin
//	go test ./src/example/admin           # runs the flow end to end
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/common/autherr"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/models/enums"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	adminconfig "github.com/better-go-auth/goauth/src/plugins/admin/config"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	adminrepo "github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/danielgtaylor/huma/v2"
)

// Statements: every resource/action that exists. The admin plugin's own user/session statements plus
// an app-specific "report" resource.
var statements = adminconfig.DefaultStatements.Merge(access.Statements{
	"report": {"read", "export"},
})

// ac is better-auth's createAccessControl(statements).
var ac = access.NewAccessControl(statements)

// roles is better-auth's admin `roles` option. Once set, only these roles exist: a user whose role is
// not listed here has no permissions, and /admin/set-role rejects unknown roles.
var roles = map[string]access.Role{
	// admin: better-auth's default admin role (everything but user:impersonate-admins) + all reports
	"admin": ac.NewRole(adminconfig.AdminAC.Statements().Merge(access.Statements{"report": {"read", "export"}})),
	// support: may look users up and read reports, nothing else
	"support": ac.NewRole(access.Statements{"user": {"list", "get"}, "report": {"read"}}),
	// user: no admin permissions
	"user": ac.NewRole(access.Statements{}),
}

// PermReportRead is the permission GET /api/example/reports requires.
var PermReportRead = access.Req(map[string][]string{"report": {"read"}})

// ErrNotAllowedToReadReports is the better-auth style error of the reports route ({"code": ...}).
var ErrNotAllowedToReadReports = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_READ_REPORTS", "You are not allowed to read reports")

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: the admin plugin with the custom access control and roles. Without WithRoles the plugin
	// uses better-auth's default roles: "admin" (all admin permissions) and "user" (none).
	adminPlugin, err := admin.New(adminrepo.AdminRepositories{},
		admin.WithAccessControl(ac),
		admin.WithRoles(roles),
		// roles that count as admins: impersonating them needs user:impersonate-admins
		admin.WithAdminRoles(enums.Admin),
		admin.WithDefaultRole(enums.User),
	)
	if err != nil {
		return nil, err
	}
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{adminPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 4: protected routes of your own: any signed-in user, and one that needs report:read
	app.AddMeRoute()
	addReportsRoute(app, adminPlugin)
	return app, nil
}

// ReportsOutput is the body of GET /api/example/reports.
type ReportsOutput struct {
	Body struct {
		Reports []string `json:"reports"`
		Role    string   `json:"role"`
	}
}

// addReportsRoute registers GET /api/example/reports, protected by an admin-plugin permission.
func addReportsRoute(app *exkit.App, adminPlugin *admin.Plugin) {
	huma.Register(app.API, huma.Operation{
		OperationID: "Example_Reports",
		Method:      http.MethodGet,
		Path:        "/api/example/reports",
		Summary:     "Reports (needs the report:read permission)",
		Tags:        []string{"Example"},
		// Step 1: the Authenticate middleware rejects requests without a valid session (401)
		Middlewares: huma.Middlewares{app.Auth.MiddlewareInt().Authenticate()},
	}, func(ctx context.Context, _ *struct{}) (*ReportsOutput, error) {
		// Step 2: the session in the context carries the user ID and role
		s, ok := authenticator.SessionFromContext(ctx)
		if !ok {
			return nil, huma.Error401Unauthorized("not signed in")
		}
		// Step 3: the same check the /admin/* routes use: AdminUserIDs pass, otherwise one of the
		// user's comma-separated roles must grant report:read
		if !adminPlugin.Config().HasPermission(s.User.ID, s.User.Role, PermReportRead) {
			return nil, humatypes.RespondErr(ErrNotAllowedToReadReports)
		}
		out := &ReportsOutput{}
		out.Body.Reports = []string{"signups-weekly", "active-sessions"}
		out.Body.Role = s.User.Role
		return out, nil
	})
}

// seedAdmin bootstraps the first admin: nobody can call /admin/set-role before an admin exists. It
// creates the account with role "admin" through the plugin's service (no HTTP, no permission check).
// An existing account is left as it is. Alternatives: admin.WithAdminUserIDs(id) (that user passes
// every permission check), or setting the user's role column to "admin" in the database.
func seedAdmin(ctx context.Context, auth *goauth.GoAuth, email, password string) error {
	// Step 1: find the admin plugin
	adminPlugin, ok := auth.Plugin(admin.PluginID).(*admin.Plugin)
	if !ok {
		return errors.New("admin plugin not installed")
	}
	// Step 2: create the user with the admin role; an existing email is not an error
	_, err := adminPlugin.Service().CreateUser(ctx, admindtos.AdminCreateUserInput{
		Email:    email,
		Password: password,
		Name:     "Admin",
		Role:     enums.Admin,
	}, "")
	if err != nil && !errors.Is(err, autherr.ErrEmailExists) {
		return err
	}
	return nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "admin_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	// bootstrap the first admin from the environment
	if email, password := os.Getenv("ADMIN_EMAIL"), os.Getenv("ADMIN_PASSWORD"); email != "" && password != "" {
		if err := seedAdmin(context.Background(), app.Auth, email, password); err != nil {
			log.Fatalf("seed admin: %v", err)
		}
		log.Printf("admin account: %s", email)
	}
	exkit.Serve(app.Mux)
}
