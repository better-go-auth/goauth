package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/plugins/org"
	"github.com/danielgtaylor/huma/v2"
)

const password = "Password123!"

type idBody struct {
	ID string `json:"id"`
}

type projectsBody struct {
	Projects []Project `json:"projects"`
}

// hasPermission asks POST /organization/has-permission whether the caller's role in the active
// organization grants resource:action.
func hasPermission(t *testing.T, c *exkit.Client, resource, action string) bool {
	t.Helper()
	var res struct {
		Success bool `json:"success"`
	}
	c.MustOK(c.Post("/api/auth/organization/has-permission", map[string]any{
		"permissions": map[string][]string{resource: {action}},
	}), &res)
	return res.Success
}

// mustForbidden fails unless r is goauth's 403 FORBIDDEN error.
func mustForbidden(t *testing.T, what string, r *exkit.Response) {
	t.Helper()
	if r.Status != http.StatusForbidden || r.ErrorCode() != "FORBIDDEN" {
		t.Fatalf("%s: status %d (%s), want 403 FORBIDDEN", what, r.Status, r.Body)
	}
}

func TestOrganizationAuthorizationFlow(t *testing.T) {
	outbox := &exkit.Outbox{}
	app, _, err := newApp("", outbox)
	if err != nil {
		t.Fatal(err)
	}
	owner := exkit.StartTest(t, app)

	// Step 1: the owner signs up and creates an organization; it becomes the session's active one
	owner.MustOK(owner.SignUp("owner@example.com", password, "Olivia"), nil)
	var acme idBody
	owner.MustStatus(owner.Post("/api/auth/organization/create", map[string]any{"name": "Acme", "slug": "acme"}), http.StatusCreated, &acme)
	if acme.ID == "" {
		t.Fatal("organization id missing")
	}
	// set-active is what a client calls to switch organizations (here it is already active)
	owner.MustOK(owner.Post("/api/auth/organization/set-active", map[string]any{"organizationId": acme.ID}), nil)

	// Step 2: the owner may do everything, including the custom project actions
	var apollo Project
	owner.MustStatus(owner.Post("/api/example/projects", map[string]any{"name": "Apollo"}), http.StatusCreated, &apollo)
	if apollo.OrganizationID != acme.ID {
		t.Fatalf("project org = %q, want %q", apollo.OrganizationID, acme.ID)
	}
	if !hasPermission(t, owner, "organization", "delete") || !hasPermission(t, owner, "project", "delete") {
		t.Fatal("owner should have organization:delete and project:delete")
	}

	// Step 3: the owner invites Bob as a member; the invitation ID arrives through SendInvitationEmail
	owner.MustStatus(owner.Post("/api/auth/organization/invite-member", map[string]any{"email": "bob@example.com", "role": "member"}), http.StatusCreated, nil)
	invitationID := outbox.Last("invitation", "bob@example.com")
	if invitationID == "" {
		t.Fatal("no invitation sent")
	}

	// Step 4: Bob signs up; before accepting he is no member, so the project routes refuse him
	bob := owner.Fork()
	bob.MustOK(bob.SignUp("bob@example.com", password, "Bob"), nil)
	mustForbidden(t, "bob (no active org) lists projects", bob.Get("/api/example/projects"))
	mustForbidden(t, "bob (not a member) lists projects", bob.Get("/api/example/projects", map[string]string{"X-Organization-Id": acme.ID}))

	// Step 5: Bob accepts; with the X-Organization-Id header his role is looked up in the member table
	bob.MustOK(bob.Post("/api/auth/organization/accept-invitation", map[string]any{"invitationId": invitationID}), nil)
	bob.MustOK(bob.Get("/api/example/projects", map[string]string{"X-Organization-Id": acme.ID}), nil)

	// Step 6: Bob activates the organization; as "member" he may read projects but not create them
	bob.MustOK(bob.Post("/api/auth/organization/set-active", map[string]any{"organizationId": acme.ID}), nil)
	var list projectsBody
	bob.MustOK(bob.Get("/api/example/projects"), &list)
	if len(list.Projects) != 1 || list.Projects[0].Name != "Apollo" {
		t.Fatalf("projects = %+v", list.Projects)
	}
	mustForbidden(t, "member creates project", bob.Post("/api/example/projects", map[string]any{"name": "Gemini"}))
	if !hasPermission(t, bob, "project", "read") || hasPermission(t, bob, "project", "create") {
		t.Fatal("member should have project:read only")
	}

	// Step 7: built-in endpoints follow the same roles: a member lacks invitation:create
	if hasPermission(t, bob, "invitation", "create") {
		t.Fatal("member should not have invitation:create")
	}
	mustForbidden(t, "member invites", bob.Post("/api/auth/organization/invite-member", map[string]any{"email": "carol@example.com", "role": "member"}))

	// Step 8: the owner promotes Bob to admin (member:update)
	var members struct {
		Members []struct {
			ID     string `json:"id"`
			UserID string `json:"userId"`
			Role   string `json:"role"`
		} `json:"members"`
	}
	owner.MustOK(owner.Get("/api/auth/organization/list-members"), &members)
	var bobMemberID, bobUserID string
	for _, m := range members.Members {
		if m.Role == "member" {
			bobMemberID, bobUserID = m.ID, m.UserID
		}
	}
	if bobMemberID == "" {
		t.Fatalf("bob not listed: %+v", members.Members)
	}
	owner.MustOK(owner.Post("/api/auth/organization/update-member-role", map[string]any{"memberId": bobMemberID, "role": "admin"}), nil)

	// Step 9: the new role applies at once, both to has-permission and to the project routes
	// (RequirePermission reads the member's role on every request)
	if !hasPermission(t, bob, "project", "create") {
		t.Fatal("admin should have project:create")
	}

	// Step 10: as admin Bob creates projects and invites people, but may not delete projects
	var gemini Project
	bob.MustStatus(bob.Post("/api/example/projects", map[string]any{"name": "Gemini"}), http.StatusCreated, &gemini)
	mustForbidden(t, "admin deletes project", bob.Do(http.MethodDelete, "/api/example/projects/"+gemini.ID, nil))
	bob.MustStatus(bob.Post("/api/auth/organization/invite-member", map[string]any{"email": "carol@example.com", "role": "member"}), http.StatusCreated, nil)
	if hasPermission(t, bob, "organization", "delete") {
		t.Fatal("admin should not have organization:delete")
	}

	// Step 11: only the owner deletes projects
	owner.MustStatus(owner.Do(http.MethodDelete, "/api/example/projects/"+gemini.ID, nil), http.StatusNoContent, nil)
	owner.MustOK(owner.Get("/api/example/projects"), &list)
	if len(list.Projects) != 1 {
		t.Fatalf("projects after delete = %+v", list.Projects)
	}

	// Step 12: teams (enabled in newApp): the admin creates a team (team:create), adds Bob to it, and
	// Bob makes it his active team
	var team idBody
	bob.MustOK(bob.Post("/api/auth/organization/create-team", map[string]any{"name": "Platform"}), &team)
	bob.MustOK(bob.Post("/api/auth/organization/add-team-member", map[string]any{"teamId": team.ID, "userId": bobUserID}), nil)
	var active struct {
		Session struct {
			ActiveOrganizationID string `json:"activeOrganizationId"`
			ActiveTeamID         string `json:"activeTeamId"`
		} `json:"session"`
	}
	bob.MustOK(bob.Post("/api/auth/organization/set-active-team", map[string]any{"teamId": team.ID}), &active)
	if active.Session.ActiveTeamID != team.ID || active.Session.ActiveOrganizationID != acme.ID {
		t.Fatalf("session after set-active-team = %+v", active.Session)
	}

	// Step 13: demoting or removing Bob takes effect on his next request, without a new sign-in
	owner.MustOK(owner.Post("/api/auth/organization/update-member-role", map[string]any{"memberId": bobMemberID, "role": "member"}), nil)
	mustForbidden(t, "demoted admin creates project", bob.Post("/api/example/projects", map[string]any{"name": "Mercury"}))
	owner.MustOK(owner.Post("/api/auth/organization/remove-member", map[string]any{"memberIdOrEmail": bobMemberID}), nil)
	mustForbidden(t, "removed member lists projects", bob.Get("/api/example/projects"))
}

// TestOwnerOnlyHasItsStatements shows that the owner is checked like any other role: a route needing
// an action the owner role does not list is forbidden, and has-permission agrees.
func TestOwnerOnlyHasItsStatements(t *testing.T) {
	app, orgPlugin, err := newApp("", &exkit.Outbox{})
	if err != nil {
		t.Fatal(err)
	}
	// Step 1: a route requiring an action no role is granted
	addArchiveRoute(app, orgPlugin)
	c := exkit.StartTest(t, app)

	// Step 2: the owner is refused by the middleware, and has-permission says no as well
	c.MustOK(c.SignUp("owner@example.com", password, "Olivia"), nil)
	c.MustStatus(c.Post("/api/auth/organization/create", map[string]any{"name": "Acme", "slug": "acme"}), http.StatusCreated, nil)
	mustForbidden(t, "owner archives projects", c.Post("/api/example/projects/archive", nil))
	if hasPermission(t, c, "project", "archive") {
		t.Fatal("has-permission should deny project:archive")
	}
}

// addArchiveRoute registers POST /api/example/projects/archive, which requires project:archive, an
// action no role holds (it is not even a statement of the access control).
func addArchiveRoute(app *exkit.App, orgPlugin *org.OrgPlugin) {
	huma.Register(app.API, huma.Operation{
		OperationID:   "Example_ArchiveProjects",
		Method:        http.MethodPost,
		Path:          "/api/example/projects/archive",
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{app.Auth.MiddlewareInt().Authenticate(), orgPlugin.RequirePermission("project", "archive")},
	}, func(context.Context, *struct{}) (*struct{}, error) { return nil, nil })
}
