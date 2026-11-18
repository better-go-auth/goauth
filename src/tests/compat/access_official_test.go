package compattest

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	adminconfig "github.com/better-go-auth/goauth/src/plugins/admin/config"
	adminrepo "github.com/better-go-auth/goauth/src/plugins/admin/repository"
	bearer "github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/providers/access"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestOfficialBetterAuthClient_Access runs client/test-access.mjs: the official better-auth client
// with createAccessControl roles calling admin.hasPermission and organization
// hasPermission/createRole/listRoles/getRole/updateRole/deleteRole against goauth.
// The roles below mirror the ones the script builds with createAccessControl.
func TestOfficialBetterAuthClient_Access(t *testing.T) {
	// Step 1: shared DB so plugins and server use the same connection
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:compat_access_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	// Step 2: admin plugin with custom roles (better-auth `roles` option)
	adminAC := access.NewAccessControl(adminconfig.DefaultStatements)
	adminPlugin, err := admin.New(adminrepo.AdminRepositories{},
		admin.WithAccessControl(adminAC),
		admin.WithRoles(map[string]access.Role{
			"admin":   adminconfig.AdminAC,
			"user":    adminconfig.UserAC,
			"support": adminAC.NewRole(access.Statements{"user": {"list", "get"}}),
		}),
	)
	if err != nil {
		t.Fatalf("admin plugin: %v", err)
	}

	// Step 3: organization plugin with ac + roles and dynamic access control
	orgStatements := orgconfig.DefaultStatements.Clone()
	orgStatements["project"] = []string{"create", "read", "update", "delete"}
	orgAC := access.NewAccessControl(orgStatements)
	orgPlugin, err := org.New(org.OrgOptions{Config: orgconfig.OrgConfig{
		DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{Enabled: true},
		AccessControl:        orgAC,
		AccessRoles: map[string]access.Role{
			"owner":  orgAC.NewRole(orgconfig.OwnerAC.Statements().Merge(access.Statements{"project": {"create", "read", "update", "delete"}})),
			"admin":  orgAC.NewRole(orgconfig.AdminAC.Statements().Merge(access.Statements{"project": {"create", "read", "update"}})),
			"member": orgAC.NewRole(orgconfig.MemberAC.Statements().Merge(access.Statements{"project": {"read"}})),
		},
	}})
	if err != nil {
		t.Fatalf("org plugin: %v", err)
	}

	s := NewServer(t,
		WithDB(db),
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(adminPlugin),
		WithPlugin(orgPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 4: pre-create an admin and a support user (the client cannot promote itself)
	signUpWithRole := func(email, role string) {
		res := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": "Password123!", "name": role})
		if res.Status != http.StatusOK {
			t.Fatalf("sign-up %s: %d %s", email, res.Status, res.Body)
		}
		if err := db.Model(&coremodels.User{}).Where("email = ?", email).Update("role", role).Error; err != nil {
			t.Fatalf("promote %s: %v", email, err)
		}
	}
	ts := time.Now().UnixNano()
	adminEmail := fmt.Sprintf("access-admin-%d@example.com", ts)
	supportEmail := fmt.Sprintf("access-support-%d@example.com", ts)
	signUpWithRole(adminEmail, "admin")
	signUpWithRole(supportEmail, "support")

	// Step 5: run the official client script
	RunNodeClient(t, "client", "test-access.mjs", s.URL,
		"GOAUTH_ADMIN_EMAIL="+adminEmail,
		"GOAUTH_SUPPORT_EMAIL="+supportEmail,
		"GOAUTH_PASSWORD=Password123!",
	)
}
