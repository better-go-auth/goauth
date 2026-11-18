package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

const password = "Password123!"

type userBody struct {
	ID        string  `json:"id"`
	Email     string  `json:"email"`
	Role      string  `json:"role"`
	Banned    bool    `json:"banned"`
	BanReason *string `json:"banReason"`
}

type permResult struct {
	Success bool `json:"success"`
}

// expectDenied fails unless r is a 403 with the given better-auth error code.
func expectDenied(t *testing.T, r *exkit.Response, code string) {
	t.Helper()
	if r.Status != http.StatusForbidden || r.ErrorCode() != code {
		t.Fatalf("want 403 %s, got %d %s", code, r.Status, r.Body)
	}
}

// hasPermission asks /admin/has-permission whether the client's own user has perms.
func hasPermission(c *exkit.Client, perms map[string][]string) bool {
	var out permResult
	c.MustOK(c.Post("/api/auth/admin/has-permission", map[string]any{"permissions": perms}), &out)
	return out.Success
}

func TestAdminAuthorizationFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: bootstrap the first admin, then sign in as admin
	if err := seedAdmin(context.Background(), app.Auth, "admin@example.com", password); err != nil {
		t.Fatal(err)
	}
	adminC := c.Fork()
	adminC.MustOK(adminC.SignIn("admin@example.com", password), nil)

	// Step 2: two ordinary users sign up; the admin plugin gives them the default role "user"
	alice := c.Fork()
	var signUp struct {
		User userBody `json:"user"`
	}
	alice.MustOK(alice.SignUp("alice@example.com", password, "Alice"), &signUp)
	aliceID := signUp.User.ID
	if signUp.User.Role != "user" {
		t.Fatalf("new user role = %q, want user", signUp.User.Role)
	}
	bob := c.Fork()
	bob.MustOK(bob.SignUp("bob@example.com", password, "Bob"), &signUp)
	bobID := signUp.User.ID

	// Step 3: the admin may list users (user:list); a plain user gets better-auth's error code
	var list struct {
		Users []userBody `json:"users"`
		Total int64      `json:"total"`
	}
	adminC.MustOK(adminC.Get("/api/auth/admin/list-users?limit=10"), &list)
	if list.Total != 3 {
		t.Fatalf("total = %d, want 3", list.Total)
	}
	expectDenied(t, alice.Get("/api/auth/admin/list-users"), "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS")
	expectDenied(t, alice.Post("/api/auth/admin/set-role", map[string]any{"userId": aliceID, "role": "admin"}), "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")

	// Step 4: the admin makes alice "support"; roles that are not configured are rejected
	if r := adminC.Post("/api/auth/admin/set-role", map[string]any{"userId": aliceID, "role": "ghost"}); r.Status != http.StatusBadRequest || r.ErrorCode() != "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE" {
		t.Fatalf("set unknown role: %d %s", r.Status, r.Body)
	}
	var setRole struct {
		User userBody `json:"user"`
	}
	adminC.MustOK(adminC.Post("/api/auth/admin/set-role", map[string]any{"userId": aliceID, "role": "support"}), &setRole)
	if setRole.User.Role != "support" {
		t.Fatalf("role = %q, want support", setRole.User.Role)
	}
	// alice stays signed in (like better-auth, set-role does not revoke sessions); her next request
	// already runs with the new role
	var aliceMe exkit.MeOutput
	alice.MustOK(alice.Get("/api/example/me"), &aliceMe.Body)
	if aliceMe.Body.Role != "support" {
		t.Fatalf("role after set-role = %q, want support", aliceMe.Body.Role)
	}

	// Step 5: support has exactly its permissions: list users yes, ban no
	alice.MustOK(alice.Get("/api/auth/admin/list-users"), nil)
	expectDenied(t, alice.Post("/api/auth/admin/ban-user", map[string]any{"userId": bobID}), "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")

	// Step 6: any signed-in user can ask which permissions they have
	if !hasPermission(alice, map[string][]string{"user": {"list"}, "report": {"read"}}) {
		t.Fatal("support should have user:list and report:read")
	}
	if hasPermission(alice, map[string][]string{"user": {"ban"}}) {
		t.Fatal("support must not have user:ban")
	}
	if hasPermission(bob, map[string][]string{"user": {"list"}}) {
		t.Fatal("user must not have user:list")
	}
	if !hasPermission(adminC, map[string][]string{"user": {"ban", "impersonate"}, "report": {"export"}}) {
		t.Fatal("admin should have user:ban,impersonate and report:export")
	}

	// Step 7: your own route, guarded by report:read: support and admin pass, a plain user gets 403
	var reports ReportsOutput
	alice.MustOK(alice.Get("/api/example/reports"), &reports.Body)
	if len(reports.Body.Reports) == 0 || reports.Body.Role != "support" {
		t.Fatalf("reports = %+v", reports.Body)
	}
	adminC.MustOK(adminC.Get("/api/example/reports"), nil)
	expectDenied(t, bob.Get("/api/example/reports"), "YOU_ARE_NOT_ALLOWED_TO_READ_REPORTS")
	if r := c.Fork().Get("/api/example/reports"); r.Status != http.StatusUnauthorized {
		t.Fatalf("reports without session: %d, want 401", r.Status)
	}

	// Step 8: the admin bans bob: his sessions are revoked and he cannot sign in again
	var ban struct {
		User userBody `json:"user"`
	}
	adminC.MustOK(adminC.Post("/api/auth/admin/ban-user", map[string]any{"userId": bobID, "banReason": "spam"}), &ban)
	if !ban.User.Banned || ban.User.BanReason == nil || *ban.User.BanReason != "spam" {
		t.Fatalf("ban = %+v", ban.User)
	}
	if r := bob.Get("/api/example/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("banned user's old session: %d, want 401 (%s)", r.Status, r.Body)
	}
	expectDenied(t, bob.SignIn("bob@example.com", password), "BANNED_USER")

	// Step 9: unban, and bob can sign in again
	adminC.MustOK(adminC.Post("/api/auth/admin/unban-user", map[string]any{"userId": bobID}), nil)
	bob.MustOK(bob.SignIn("bob@example.com", password), nil)

	// Step 10: the admin impersonates bob; the new session records who is impersonating
	type sessionBody struct {
		Session struct {
			UserID         string  `json:"userId"`
			Token          string  `json:"token"`
			ImpersonatedBy *string `json:"impersonatedBy"`
		} `json:"session"`
	}
	var imp sessionBody
	adminC.MustOK(adminC.Post("/api/auth/admin/impersonate-user", map[string]any{"userId": bobID}), &imp)
	if imp.Session.UserID != bobID || imp.Session.ImpersonatedBy == nil || *imp.Session.ImpersonatedBy == "" {
		t.Fatalf("impersonation session = %+v", imp.Session)
	}
	// the admin's browser now runs as bob: the session cookie holds the impersonation session and the
	// admin's own session is kept in the admin_session cookie
	var sess sessionBody
	adminC.MustOK(adminC.Get("/api/auth/get-session"), &sess)
	if sess.Session.UserID != bobID || sess.Session.ImpersonatedBy == nil {
		t.Fatalf("get-session while impersonating = %+v", sess.Session)
	}
	// while impersonating, the admin has bob's permissions only
	expectDenied(t, adminC.Get("/api/example/reports"), "YOU_ARE_NOT_ALLOWED_TO_READ_REPORTS")

	// Step 11: stop impersonating ends the impersonation session and restores the admin's own session
	adminC.MustOK(adminC.Post("/api/auth/admin/stop-impersonating", map[string]any{}), nil)
	var me exkit.MeOutput
	adminC.MustOK(adminC.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "admin@example.com" || me.Body.Role != "admin" {
		t.Fatalf("admin me after stop-impersonating = %+v", me.Body)
	}
	// stop-impersonating on a normal session is rejected
	if r := bob.Post("/api/auth/admin/stop-impersonating", map[string]any{}); r.Status != http.StatusBadRequest {
		t.Fatalf("stop-impersonating without impersonation: %d %s", r.Status, r.Body)
	}

	// Step 12: support cannot impersonate, and impersonating another admin needs user:impersonate-admins
	expectDenied(t, alice.Post("/api/auth/admin/impersonate-user", map[string]any{"userId": bobID}), "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS")
	if err := seedAdmin(context.Background(), app.Auth, "admin2@example.com", password); err != nil {
		t.Fatal(err)
	}
	var found struct {
		Users []userBody `json:"users"`
	}
	adminC.MustOK(adminC.Get("/api/auth/admin/list-users?searchField=email&searchValue=admin2@example.com"), &found)
	if len(found.Users) != 1 {
		t.Fatalf("admin2 lookup: %+v", found.Users)
	}
	expectDenied(t, adminC.Post("/api/auth/admin/impersonate-user", map[string]any{"userId": found.Users[0].ID}), "YOU_CANNOT_IMPERSONATE_ADMINS")
}
