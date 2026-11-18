// Command org runs goauth with the organization plugin and shows how organization roles authorize
// both goauth's own /organization/* endpoints and routes of your own (/api/example/projects).
//
//	go run ./src/example/org            # http://localhost:8080/docs
//	go test ./src/example/org           # runs the flow end to end
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

// projectActions are the actions of the app-specific "project" resource.
var projectActions = []string{"create", "read", "delete"}

// accessControl is better-auth's default organization statements plus the "project" resource.
// It mirrors `createAccessControl({...defaultStatements, project: [...]})` in better-auth.
var accessControl = access.NewAccessControl(orgconfig.DefaultStatements.Merge(access.Statements{
	"project": projectActions,
}))

// roles extends better-auth's default owner/admin/member roles with project permissions. Setting
// AccessRoles replaces the defaults, so every role the app uses must be listed here.
func roles() map[string]access.Role {
	return map[string]access.Role{
		// owner: everything (better-auth ownerAc) + every project action
		"owner": accessControl.NewRole(orgconfig.OwnerAC.Statements().Merge(access.Statements{
			"project": projectActions,
		})),
		// admin: everything but organization:delete (better-auth adminAc) + create/read projects
		"admin": accessControl.NewRole(orgconfig.AdminAC.Statements().Merge(access.Statements{
			"project": {"create", "read"},
		})),
		// member: ac:read (better-auth memberAc) + read projects
		"member": accessControl.NewRole(orgconfig.MemberAC.Statements().Merge(access.Statements{
			"project": {"read"},
		})),
	}
}

// Project is the app-owned resource the example protects with organization permissions.
type Project struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
}

// projectStore keeps projects in memory, per organization.
type projectStore struct {
	mu   sync.Mutex
	byID map[string]Project
}

// newApp builds the example server. dbPath "" uses an in-memory database (tests). outbox receives the
// invitation emails.
func newApp(dbPath string, outbox *exkit.Outbox) (*exkit.App, *org.OrgPlugin, error) {
	// Step 1: open the database (the org plugin's repositories use it directly)
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, nil, err
	}
	// Step 2: configure the plugin: custom access control, teams, and the invitation email sender
	orgPlugin, err := org.New(org.OrgOptions{Config: orgconfig.OrgConfig{
		AccessControl: accessControl,
		AccessRoles:   roles(),
		Teams:         &orgconfig.TeamsConfig{Enabled: true},
		InvitaionConfig: orgconfig.InvitaionConfig{
			// a real app emails a link such as https://app.example.com/accept-invitation/<id>
			SendInvitationEmail: func(_ context.Context, in orgconfig.SendInvitationInput) error {
				outbox.Put("invitation", in.Email, in.ID)
				return nil
			},
		},
		// OrgNeedsApproval: true would keep new organizations "pending" until a user with the
		// system role "admin" calls POST /api/auth/admin/organization/approve.
	}})
	if err != nil {
		return nil, nil, err
	}
	// Step 3: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{orgPlugin},
	})
	if err != nil {
		return nil, nil, err
	}
	// Step 4: routes of your own, authorized by the caller's role in the active organization
	app.AddMeRoute()
	addProjectRoutes(app, orgPlugin)
	return app, orgPlugin, nil
}

// ProjectsOutput is the body of GET /api/example/projects.
type ProjectsOutput struct {
	Body struct {
		Projects []Project `json:"projects"`
	}
}

// ProjectOutput is the body of POST /api/example/projects.
type ProjectOutput struct {
	Body Project
}

// OrgScope is the optional X-Organization-Id header. RequirePermission uses it only when the session
// has no active organization, so the handlers resolve the organization the same way (see orgID).
type OrgScope struct {
	OrganizationID string `header:"X-Organization-Id" doc:"Organization ID, used when the session has no active organization"`
}

// ListProjectsInput is the input of GET /api/example/projects.
type ListProjectsInput struct {
	OrgScope
}

// CreateProjectInput is the body of POST /api/example/projects.
type CreateProjectInput struct {
	OrgScope
	Body struct {
		Name string `json:"name" minLength:"1"`
	}
}

// DeleteProjectInput identifies the project of DELETE /api/example/projects/{id}.
type DeleteProjectInput struct {
	OrgScope
	ID string `path:"id"`
}

// addProjectRoutes registers the project routes. Each one runs goauth's Authenticate middleware first
// (it resolves the session), then the org plugin's RequirePermission(resource, action) middleware,
// which looks up the caller's member row and answers 403 unless that role grants the permission.
func addProjectRoutes(app *exkit.App, orgPlugin *org.OrgPlugin) {
	store := &projectStore{byID: map[string]Project{}}
	authn := app.Auth.MiddlewareInt().Authenticate()

	// Step 1: GET lists the active organization's projects (project:read: member, admin, owner)
	huma.Register(app.API, huma.Operation{
		OperationID: "Example_ListProjects",
		Method:      http.MethodGet,
		Path:        "/api/example/projects",
		Summary:     "List the active organization's projects (project:read)",
		Tags:        []string{"Example"},
		Middlewares: huma.Middlewares{authn, orgPlugin.RequirePermission("project", "read")},
	}, func(ctx context.Context, in *ListProjectsInput) (*ProjectsOutput, error) {
		orgID := in.orgID(ctx)
		out := &ProjectsOutput{}
		out.Body.Projects = []Project{}
		store.mu.Lock()
		defer store.mu.Unlock()
		for _, p := range store.byID {
			if p.OrganizationID == orgID {
				out.Body.Projects = append(out.Body.Projects, p)
			}
		}
		return out, nil
	})

	// Step 2: POST creates a project (project:create: admin, owner)
	huma.Register(app.API, huma.Operation{
		OperationID:   "Example_CreateProject",
		Method:        http.MethodPost,
		Path:          "/api/example/projects",
		Summary:       "Create a project in the active organization (project:create)",
		Tags:          []string{"Example"},
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{authn, orgPlugin.RequirePermission("project", "create")},
	}, func(ctx context.Context, in *CreateProjectInput) (*ProjectOutput, error) {
		p := Project{ID: uuid.NewString(), OrganizationID: in.orgID(ctx), Name: in.Body.Name}
		store.mu.Lock()
		store.byID[p.ID] = p
		store.mu.Unlock()
		return &ProjectOutput{Body: p}, nil
	})

	// Step 3: DELETE removes a project (project:delete: owner only)
	huma.Register(app.API, huma.Operation{
		OperationID:   "Example_DeleteProject",
		Method:        http.MethodDelete,
		Path:          "/api/example/projects/{id}",
		Summary:       "Delete a project of the active organization (project:delete)",
		Tags:          []string{"Example"},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{authn, orgPlugin.RequirePermission("project", "delete")},
	}, func(ctx context.Context, in *DeleteProjectInput) (*struct{}, error) {
		store.mu.Lock()
		defer store.mu.Unlock()
		// a project of another organization is reported as missing, never deleted
		if p, ok := store.byID[in.ID]; !ok || p.OrganizationID != in.orgID(ctx) {
			return nil, huma.Error404NotFound("project not found")
		}
		delete(store.byID, in.ID)
		return nil, nil
	})
}

// orgID returns the organization the request was authorized for, resolved like RequirePermission does:
// the session's active organization, else the X-Organization-Id header.
func (o OrgScope) orgID(ctx context.Context) string {
	if s, ok := authenticator.SessionFromContext(ctx); ok && s.Session.ActiveOrganizationID != nil && *s.Session.ActiveOrganizationID != "" {
		return *s.Session.ActiveOrganizationID
	}
	return o.OrganizationID
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "org_example.db"
	}
	app, _, err := newApp(dbPath, &exkit.Outbox{})
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
