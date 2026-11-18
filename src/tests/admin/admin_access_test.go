package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	serv_interfaces "github.com/better-go-auth/goauth/src/app/services/interfaces"
	loc_conf "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
	adminrepo "github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/better-go-auth/goauth/src/providers/access"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

// setupAdminAccessEnv boots goauth with the bearer plugin and an admin plugin configured with opts.
func setupAdminAccessEnv(t *testing.T, opts ...admin.Option) *helpers.TestEnv {
	t.Helper()
	// Step 1: database + admin plugin with the requested options
	db := helpers.SetupTestDB(t, helpers.DBTypeSQLite)
	adminPlugin, err := admin.New(adminrepo.AdminRepositories{}, opts...)
	if err != nil {
		t.Fatalf("admin plugin: %v", err)
	}
	// Step 2: goauth on a fresh mux
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Admin Access Test API", "1.0.0"))
	auth, err := goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		Conn:             db,
		SecondaryStorage: sec_storage.New(),
		AuthConfig: loc_conf.AuthConfig{
			BaseURL:        "http://localhost:3000",
			Secret:         "secret-key-32-chars-long-for-test!",
			TrustedOrigins: []string{"http://127.0.0.1:*", "http://localhost:*"},
		},
		Plugins: []plugin.Plugin{bearer.New(bearerconfig.DefaultConfig()), adminPlugin},
	})
	if err != nil {
		t.Fatalf("setup goauth: %v", err)
	}
	// Step 3: serve over HTTP so PostJSON works
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &helpers.TestEnv{Options: auth.Options(), DB: db, Auth: auth, HumaAPI: api, Mux: mux, Server: srv, BaseURL: srv.URL}
}

// userWithRole creates a user with role and returns its id and signed bearer header.
func userWithRole(t *testing.T, env *helpers.TestEnv, email string, role enums.Role) (string, map[string]string) {
	t.Helper()
	u := &models.User{UserDto: models.UserDto{FirstName: "U", Email: email, EmailVerified: true, Role: role}}
	if err := env.DB.Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	swu, err := env.Auth.Sessions().Create(context.Background(), u, serv_interfaces.SessionMeta{}, serv_interfaces.SessionCreateOptions{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return u.ID, map[string]string{"Authorization": helpers.SignedBearerAuth(swu.Session.Token, env.Options.Secret)}
}

func expectCode(t *testing.T, resp *http.Response, body string, status int, code string) {
	t.Helper()
	if resp.StatusCode != status || !strings.Contains(body, code) {
		t.Fatalf("expected %d %s, got %d: %s", status, code, resp.StatusCode, body)
	}
}

func hasPerm(t *testing.T, env *helpers.TestEnv, hdr map[string]string, body any) admindtos.AdminHasPermissionResponse {
	t.Helper()
	resp, raw := env.PostJSON("/api/auth/admin/has-permission", body, hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("has-permission: %d %s", resp.StatusCode, raw)
	}
	var out admindtos.AdminHasPermissionResponse
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("decode: %v %s", err, raw)
	}
	return out
}

// TestAdminAccess_DefaultRoles checks better-auth's default admin/user roles on routes and has-permission.
func TestAdminAccess_DefaultRoles(t *testing.T) {
	env := setupAdminAccessEnv(t)
	_, adminHdr := userWithRole(t, env, "admin@x.com", enums.Admin)
	_, userHdr := userWithRole(t, env, "user@x.com", enums.User)

	// Step 1: admin passes, user gets better-auth's specific error code
	resp, body := env.GetJSON("/api/auth/admin/list-users", adminHdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin list-users: %d %s", resp.StatusCode, body)
	}
	resp, body = env.GetJSON("/api/auth/admin/list-users", userHdr)
	expectCode(t, resp, body, http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS")
	resp, body = env.PostJSON("/api/auth/admin/ban-user", map[string]any{"userId": "x"}, userHdr)
	expectCode(t, resp, body, http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")

	// Step 2: has-permission checks the session user's own role
	if !hasPerm(t, env, adminHdr, map[string]any{"permissions": map[string][]string{"user": {"list", "ban"}}}).Success {
		t.Fatal("admin should have user:list,ban")
	}
	if hasPerm(t, env, adminHdr, map[string]any{"permissions": map[string][]string{"user": {"impersonate-admins"}}}).Success {
		t.Fatal("default admin must not have impersonate-admins")
	}
	if hasPerm(t, env, userHdr, map[string]any{"permission": map[string][]string{"user": {"list"}}}).Success {
		t.Fatal("user should not have user:list")
	}
	// Step 3: missing permissions -> 400
	resp, body = env.PostJSON("/api/auth/admin/has-permission", map[string]any{}, userHdr)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", resp.StatusCode, body)
	}
}

// TestAdminAccess_AdminRolesWithoutStatements follows better-auth: an AdminRoles entry that is not in the
// role map has no admin permissions.
func TestAdminAccess_AdminRolesWithoutStatements(t *testing.T) {
	env := setupAdminAccessEnv(t, admin.WithAdminRoles("admin", "superadmin"))
	_, superHdr := userWithRole(t, env, "super@x.com", enums.Role("superadmin"))

	// Step 1: list-users needs user:list, which "superadmin" does not have
	resp, body := env.GetJSON("/api/auth/admin/list-users", superHdr)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("superadmin list-users: expected 403, got %d %s", resp.StatusCode, body)
	}
	// Step 2: has-permission agrees
	if hasPerm(t, env, superHdr, map[string]any{"permissions": map[string][]string{"session": {"revoke"}}}).Success {
		t.Fatal("superadmin should not have session:revoke without GoAuth.AdminRolesFullAccess")
	}
}

// TestAdminAccess_BackwardCompatAdminRoles keeps goauth's old behaviour behind GoAuth.AdminRolesFullAccess:
// any AdminRoles entry has full access.
func TestAdminAccess_BackwardCompatAdminRoles(t *testing.T) {
	env := setupAdminAccessEnv(t, admin.WithAdminRoles("superadmin"), admin.WithAdminRolesFullAccess(true))
	_, superHdr := userWithRole(t, env, "super@x.com", enums.Role("superadmin"))
	targetID, _ := userWithRole(t, env, "t@x.com", enums.User)

	for _, path := range []string{"/api/auth/admin/list-users"} {
		resp, body := env.GetJSON(path, superHdr)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("superadmin %s: %d %s", path, resp.StatusCode, body)
		}
	}
	resp, body := env.PostJSON("/api/auth/admin/ban-user", map[string]any{"userId": targetID}, superHdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("superadmin ban: %d %s", resp.StatusCode, body)
	}
	if !hasPerm(t, env, superHdr, map[string]any{"permissions": map[string][]string{"session": {"revoke"}}}).Success {
		t.Fatal("superadmin should have session:revoke")
	}
}

// TestAdminAccess_CustomRoles follows better-auth exactly once custom roles are configured.
func TestAdminAccess_CustomRoles(t *testing.T) {
	ac := access.NewAccessControl(access.Statements{
		"user":    {"create", "list", "set-role", "ban", "impersonate", "impersonate-admins", "delete", "set-password", "set-email", "get", "update"},
		"session": {"list", "revoke", "delete"},
	})
	roles := map[string]access.Role{
		"admin":   ac.NewRole(access.Statements{"user": {"list", "get", "set-role", "impersonate", "impersonate-admins", "ban"}, "session": {"list"}}),
		"support": ac.NewRole(access.Statements{"user": {"list", "get"}}),
		"user":    ac.NewRole(access.Statements{"user": {}}),
	}
	env := setupAdminAccessEnv(t, admin.WithAccessControl(ac), admin.WithRoles(roles))
	_, adminHdr := userWithRole(t, env, "a@x.com", enums.Admin)
	_, supportHdr := userWithRole(t, env, "s@x.com", enums.Role("support"))
	_, multiHdr := userWithRole(t, env, "m@x.com", enums.Role("user,support"))
	targetID, _ := userWithRole(t, env, "t@x.com", enums.User)
	otherAdminID, _ := userWithRole(t, env, "a2@x.com", enums.Admin)

	// Step 1: a role outside AdminRoles gets exactly its permissions
	resp, body := env.GetJSON("/api/auth/admin/list-users", supportHdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("support list-users: %d %s", resp.StatusCode, body)
	}
	resp, body = env.PostJSON("/api/auth/admin/ban-user", map[string]any{"userId": targetID}, supportHdr)
	expectCode(t, resp, body, http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
	// Step 2: multi-role strings are split
	resp, body = env.GetJSON("/api/auth/admin/list-users", multiHdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("multi-role list-users: %d %s", resp.StatusCode, body)
	}
	// Step 3: the admin role lacks remove-user here
	resp, body = env.PostJSON("/api/auth/admin/remove-user", map[string]any{"userId": targetID}, adminHdr)
	expectCode(t, resp, body, http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS")
	// Step 4: setting a role that is not configured is rejected
	resp, body = env.PostJSON("/api/auth/admin/set-role", map[string]any{"userId": targetID, "role": "ghost"}, adminHdr)
	expectCode(t, resp, body, http.StatusBadRequest, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE")
	// Step 5: update-user field permissions (email needs user:set-email, which needs user:update first)
	resp, body = env.PostJSON("/api/auth/admin/update-user", map[string]any{"userId": targetID, "data": map[string]any{"name": "x"}}, adminHdr)
	expectCode(t, resp, body, http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS")
	// Step 6: this admin role has impersonate-admins, so it may impersonate another admin
	resp, body = env.PostJSON("/api/auth/admin/impersonate-user", map[string]any{"userId": otherAdminID}, adminHdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("impersonate admin with impersonate-admins: %d %s", resp.StatusCode, body)
	}
	// Step 7: has-permission with OR-less multi resource request
	if !hasPerm(t, env, supportHdr, map[string]any{"permissions": map[string][]string{"user": {"list", "get"}}}).Success {
		t.Fatal("support should have user:list,get")
	}
	if hasPerm(t, env, supportHdr, map[string]any{"permissions": map[string][]string{"user": {"list"}, "session": {"list"}}}).Success {
		t.Fatal("support should not have session:list")
	}
}

// TestAdminAccess_ImpersonateAdmins covers YOU_CANNOT_IMPERSONATE_ADMINS, adminUserIds and allowImpersonatingAdmins.
func TestAdminAccess_ImpersonateAdmins(t *testing.T) {
	t.Run("blocked by default", func(t *testing.T) {
		env := setupAdminAccessEnv(t)
		_, adminHdr := userWithRole(t, env, "a@x.com", enums.Admin)
		otherAdminID, _ := userWithRole(t, env, "a2@x.com", enums.Role("user,admin"))
		resp, body := env.PostJSON("/api/auth/admin/impersonate-user", map[string]any{"userId": otherAdminID}, adminHdr)
		expectCode(t, resp, body, http.StatusForbidden, "YOU_CANNOT_IMPERSONATE_ADMINS")
	})
	t.Run("allowImpersonatingAdmins", func(t *testing.T) {
		env := setupAdminAccessEnv(t, admin.WithAllowImpersonatingAdmins(true))
		_, adminHdr := userWithRole(t, env, "a@x.com", enums.Admin)
		otherAdminID, _ := userWithRole(t, env, "a2@x.com", enums.Admin)
		resp, body := env.PostJSON("/api/auth/admin/impersonate-user", map[string]any{"userId": otherAdminID}, adminHdr)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d %s", resp.StatusCode, body)
		}
	})
	t.Run("adminUserIds", func(t *testing.T) {
		// a plain "user" listed in adminUserIds passes every check, and is itself protected from impersonation
		env := setupAdminAccessEnv(t, admin.WithAdminUserIDs("root-id"))
		root := &models.User{Base: models.Base{ID: "root-id"}, UserDto: models.UserDto{FirstName: "Root", Email: "root@x.com", Role: enums.User}}
		if err := env.DB.Create(root).Error; err != nil {
			t.Fatal(err)
		}
		swu, err := env.Auth.Sessions().Create(context.Background(), root, serv_interfaces.SessionMeta{}, serv_interfaces.SessionCreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		rootHdr := map[string]string{"Authorization": helpers.SignedBearerAuth(swu.Session.Token, env.Options.Secret)}
		_, adminHdr := userWithRole(t, env, "a@x.com", enums.Admin)
		resp, body := env.GetJSON("/api/auth/admin/list-users", rootHdr)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("adminUserIds list-users: %d %s", resp.StatusCode, body)
		}
		if !hasPerm(t, env, rootHdr, map[string]any{"permissions": map[string][]string{"user": {"impersonate-admins"}}}).Success {
			t.Fatal("adminUserIds should have every permission")
		}
		resp, body = env.PostJSON("/api/auth/admin/impersonate-user", map[string]any{"userId": "root-id"}, adminHdr)
		expectCode(t, resp, body, http.StatusForbidden, "YOU_CANNOT_IMPERSONATE_ADMINS")
	})
}

// TestAdminAccess_InvalidAdminRoles mirrors better-auth's init-time check.
func TestAdminAccess_InvalidAdminRoles(t *testing.T) {
	_, err := admin.New(adminrepo.AdminRepositories{}, admin.WithAdminRoles("boss"), admin.WithRoles(map[string]access.Role{"admin": access.NewRole(access.Statements{})}))
	if err == nil || !strings.Contains(err.Error(), "invalid admin roles") {
		t.Fatalf("expected invalid admin roles error, got %v", err)
	}
}
