package compattest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/config"
	coremodels "github.com/better-go-auth/goauth/src/models"
	bearer "github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgdtos "github.com/better-go-auth/goauth/src/plugins/org/dtos"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestOfficialBetterAuthClient(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed, skipping official better-auth/client test")
	}

	clientScript := filepath.Join("client", "test-flow.mjs")
	if _, err := os.Stat(clientScript); err != nil {
		t.Fatalf("client test script not found: %v", err)
	}

	s := NewServer(t, WithConfig(func(c *config.AuthConfig) {
		compatMode(c)
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
	}))

	cmd := exec.Command("node", "test-flow.mjs")
	cmd.Dir = "client"
	cmd.Env = append(os.Environ(), "GOAUTH_URL="+s.URL)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official better-auth/client test failed: %v\nOutput:\n%s", err, string(output))
	}

	t.Logf("official better-auth/client output:\n%s", string(output))
}

func TestOfficialBetterAuthClient_Bearer(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed, skipping official better-auth/client bearer test")
	}

	clientScript := filepath.Join("client", "test-bearer.mjs")
	if _, err := os.Stat(clientScript); err != nil {
		t.Fatalf("client test script not found: %v", err)
	}

	s := NewServer(t,
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	cmd := exec.Command("node", "test-bearer.mjs")
	cmd.Dir = "client"
	cmd.Env = append(os.Environ(), "GOAUTH_URL="+s.URL)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official better-auth/client bearer test failed: %v\nOutput:\n%s", err, string(output))
	}

	t.Logf("official better-auth/client bearer output:\n%s", string(output))
}

func TestOfficialBetterAuthClient_JWT(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed, skipping official better-auth/client jwt test")
	}

	clientScript := filepath.Join("client", "test-jwt.mjs")
	if _, err := os.Stat(clientScript); err != nil {
		t.Fatalf("client test script not found: %v", err)
	}

	s := NewServer(t,
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(jwtplugin.New(jwtconfig.DefaultConfig())),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	cmd := exec.Command("node", "test-jwt.mjs")
	cmd.Dir = "client"
	cmd.Env = append(os.Environ(), "GOAUTH_URL="+s.URL)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official better-auth/client jwt test failed: %v\nOutput:\n%s", err, string(output))
	}

	t.Logf("official better-auth/client jwt output:\n%s", string(output))
}

func TestOfficialBetterAuthClient_Org(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed, skipping official better-auth/client org test")
	}

	clientScript := filepath.Join("client", "test-org.mjs")
	if _, err := os.Stat(clientScript); err != nil {
		t.Fatalf("client test script not found: %v", err)
	}

	// Step 1: Prepare shared DB for primary Org server and hook/email trackers
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:compat_org_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	var mu sync.Mutex
	hookEvents := make([]string, 0)
	recordHook := func(name string) {
		mu.Lock()
		defer mu.Unlock()
		hookEvents = append(hookEvents, name)
	}
	var invitationEmailsSent int32

	orgLimit := 2
	memLimit := 3
	invLimit := 5
	maxTeams := 2
	maxTeamMembers := 2
	reinviteTrue := true
	defaultTeamEnabled := true

	orgPlugin, err := org.New(org.OrgOptions{Config: orgconfig.OrgConfig{
		OrganizationLimit:                    &orgLimit,
		MembershipLimit:                      &memLimit,
		InvitationLimit:                      &invLimit,
		CancelPendingInvitationsOnReInvite:   &reinviteTrue,
		RequireEmailVerificationOnInvitation: true,
		InvitaionConfig: orgconfig.InvitaionConfig{
			InvitationExpiresIn: 2 * time.Hour,
			SendInvitationEmail: func(ctx context.Context, input orgconfig.SendInvitationInput) error {
				atomic.AddInt32(&invitationEmailsSent, 1)
				return nil
			},
		},
		Teams: &orgconfig.TeamsConfig{
			Enabled: true,
			DefaultTeam: &orgconfig.DefaultTeamConfig{
				Enabled: &defaultTeamEnabled,
				CustomCreateDefaultTeam: func(ctx context.Context, o *orgmodels.Organization) (*orgmodels.Team, error) {
					now := coremodels.TimeNow()
					team := &orgmodels.Team{
						Base:           coremodels.Base{ID: coremodels.NewID(), CreatedAt: now, UpdatedAt: now},
						Name:           "Core-" + o.Name,
						OrganizationID: o.ID,
					}
					// the hook runs inside the plugin's transaction (ctx)
					return team, gormutil.GetDB(ctx, db).Create(team).Error
				},
			},
			MaximumTeams:          &maxTeams,
			MaximumMembersPerTeam: &maxTeamMembers,
			AllowRemovingAllTeams: false,
		},
		OrganizationHooks: orgconfig.OrganizationHooks{
			BeforeCreateOrganization: func(ctx context.Context, data orgconfig.BeforeCreateOrgData) (*orgdtos.CreateOrgInput, error) {
				recordHook("beforeCreateOrg")
				return nil, nil
			},
			AfterCreateOrganization: func(ctx context.Context, data orgconfig.AfterCreateOrgData) error {
				recordHook("afterCreateOrg")
				return nil
			},
			BeforeUpdateOrganization: func(ctx context.Context, data orgconfig.BeforeUpdateOrgData) (*orgdtos.UpdateOrgInput, error) {
				recordHook("beforeUpdateOrg")
				return nil, nil
			},
			AfterUpdateOrganization: func(ctx context.Context, data orgconfig.AfterUpdateOrgData) error {
				recordHook("afterUpdateOrg")
				return nil
			},
			BeforeDeleteOrganization: func(ctx context.Context, data orgconfig.BeforeDeleteOrgData) error {
				recordHook("beforeDeleteOrg")
				return nil
			},
			AfterDeleteOrganization: func(ctx context.Context, data orgconfig.AfterDeleteOrgData) error {
				recordHook("afterDeleteOrg")
				return nil
			},
			BeforeAddMember: func(ctx context.Context, data orgconfig.BeforeAddMemberData) (*orgmodels.Member, error) {
				recordHook("beforeAddMember")
				return nil, nil
			},
			AfterAddMember: func(ctx context.Context, data orgconfig.AfterAddMemberData) error {
				recordHook("afterAddMember")
				return nil
			},
			BeforeUpdateMemberRole: func(ctx context.Context, data orgconfig.BeforeUpdateMemberRoleData) (*string, error) {
				recordHook("beforeUpdateMemberRole")
				return nil, nil
			},
			AfterUpdateMemberRole: func(ctx context.Context, data orgconfig.AfterUpdateMemberRoleData) error {
				recordHook("afterUpdateMemberRole")
				return nil
			},
			BeforeRemoveMember: func(ctx context.Context, data orgconfig.BeforeRemoveMemberData) error {
				recordHook("beforeRemoveMember")
				return nil
			},
			AfterRemoveMember: func(ctx context.Context, data orgconfig.AfterRemoveMemberData) error {
				recordHook("afterRemoveMember")
				return nil
			},
			BeforeCreateInvitation: func(ctx context.Context, data orgconfig.BeforeCreateInvitationData) (*orgdtos.InviteMemberInput, error) {
				recordHook("beforeCreateInvitation")
				return nil, nil
			},
			AfterCreateInvitation: func(ctx context.Context, data orgconfig.AfterCreateInvitationData) error {
				recordHook("afterCreateInvitation")
				return nil
			},
			BeforeAcceptInvitation: func(ctx context.Context, data orgconfig.BeforeAcceptInvitationData) error {
				recordHook("beforeAcceptInvitation")
				return nil
			},
			AfterAcceptInvitation: func(ctx context.Context, data orgconfig.AfterAcceptInvitationData) error {
				recordHook("afterAcceptInvitation")
				return nil
			},
			BeforeCreateTeam: func(ctx context.Context, data orgconfig.BeforeCreateTeamData) (*orgdtos.CreateTeamInput, error) {
				recordHook("beforeCreateTeam")
				return nil, nil
			},
			AfterCreateTeam: func(ctx context.Context, data orgconfig.AfterCreateTeamData) error {
				recordHook("afterCreateTeam")
				return nil
			},
			BeforeUpdateTeam: func(ctx context.Context, data orgconfig.BeforeUpdateTeamData) (*orgdtos.UpdateTeamInput, error) {
				recordHook("beforeUpdateTeam")
				return nil, nil
			},
			AfterUpdateTeam: func(ctx context.Context, data orgconfig.AfterUpdateTeamData) error {
				recordHook("afterUpdateTeam")
				return nil
			},
			BeforeDeleteTeam: func(ctx context.Context, data orgconfig.BeforeDeleteTeamData) error {
				recordHook("beforeDeleteTeam")
				return nil
			},
			AfterDeleteTeam: func(ctx context.Context, data orgconfig.AfterDeleteTeamData) error {
				recordHook("afterDeleteTeam")
				return nil
			},
			BeforeAddTeamMember: func(ctx context.Context, data orgconfig.BeforeAddTeamMemberData) (*orgdtos.AddTeamMemberInput, error) {
				recordHook("beforeAddTeamMember")
				return nil, nil
			},
			AfterAddTeamMember: func(ctx context.Context, data orgconfig.AfterAddTeamMemberData) error {
				recordHook("afterAddTeamMember")
				return nil
			},
			BeforeRemoveTeamMember: func(ctx context.Context, data orgconfig.BeforeRemoveTeamMemberData) error {
				recordHook("beforeRemoveTeamMember")
				return nil
			},
			AfterRemoveTeamMember: func(ctx context.Context, data orgconfig.AfterRemoveTeamMemberData) error {
				recordHook("afterRemoveTeamMember")
				return nil
			},
		},
	}})
	if err != nil {
		t.Fatalf("org plugin init: %v", err)
	}

	s := NewServer(t,
		WithDB(db),
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(orgPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Mount test-only helper endpoint to mark invitee email as verified mid-flow
	s.Mux.HandleFunc("/test/verify-user", func(w http.ResponseWriter, r *http.Request) {
		uid := r.URL.Query().Get("userId")
		if uid == "" {
			http.Error(w, "userId required", http.StatusBadRequest)
			return
		}
		// like verify-email: store the flag and refresh the user copy cached in the user's sessions
		user, err := s.Auth.Repositories().UpdateUser(r.Context(), uid, map[string]any{"emailVerified": true})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.Auth.Sessions().RefreshUser(r.Context(), user)
		w.WriteHeader(http.StatusOK)
	})

	// Step 2: Start secondary restricted server (AllowUserToCreateOrganizationFn + DisableOrganizationDeletion=true)
	rdb, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:compat_org_res_%d?mode=memory&cache=shared", time.Now().UnixNano())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open restricted sqlite: %v", err)
	}
	rOrgPlugin, err := org.New(org.OrgOptions{Config: orgconfig.OrgConfig{
		AllowUserToCreateOrganizationFn: func(ctx context.Context, user *coremodels.User) (bool, error) {
			return user != nil && user.Email == "restricted-owner@example.com", nil
		},
		DisableOrganizationDeletion: true,
	}})
	if err != nil {
		t.Fatalf("restricted org plugin init: %v", err)
	}
	rs := NewServer(t,
		WithDB(rdb),
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(rOrgPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Pre-seed restricted-owner and their org via Auth signup + OrgService
	upRes := rs.Post(t, "/api/auth/sign-up/email", map[string]any{
		"email":    "restricted-owner@example.com",
		"password": "Password123!",
		"name":     "Restricted Owner",
	})
	if upRes.Status != http.StatusOK {
		t.Fatalf("seed restricted owner failed: %d %s", upRes.Status, upRes.Body)
	}
	var upData struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	upRes.JSON(t, &upData)
	seededOrg, err := rOrgPlugin.Service().CreateOrganization(context.Background(), upData.User.ID, orgdtos.CreateOrgInput{
		Name: "Locked Org",
		Slug: "locked-org",
	})
	if err != nil {
		t.Fatalf("seed locked org failed: %v", err)
	}

	// Step 3: Execute official better-auth/client organization JS test suite
	cmd := exec.Command("node", "test-org.mjs")
	cmd.Dir = "client"
	cmd.Env = append(os.Environ(),
		"GOAUTH_URL="+s.URL,
		"GOAUTH_RESTRICTED_URL="+rs.URL,
		"GOAUTH_RESTRICTED_ORG_ID="+seededOrg.ID,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official better-auth/client org test failed: %v\nOutput:\n%s", err, string(output))
	}
	t.Logf("official better-auth/client org output:\n%s", string(output))

	// Step 4: Verify server-side side effects (SendInvitationEmail & all OrganizationHooks)
	if atomic.LoadInt32(&invitationEmailsSent) < 2 {
		t.Fatalf("expected at least 2 invitation emails sent, got %d", atomic.LoadInt32(&invitationEmailsSent))
	}
	mu.Lock()
	joinedHooks := strings.Join(hookEvents, ",")
	mu.Unlock()
	for _, expected := range []string{
		"beforeCreateOrg", "afterCreateOrg",
		"beforeUpdateOrg", "afterUpdateOrg",
		"beforeDeleteOrg", "afterDeleteOrg",
		"beforeAddMember", "afterAddMember",
		"beforeUpdateMemberRole", "afterUpdateMemberRole",
		"beforeRemoveMember", "afterRemoveMember",
		"beforeCreateInvitation", "afterCreateInvitation",
		"beforeAcceptInvitation", "afterAcceptInvitation",
		"beforeCreateTeam", "afterCreateTeam",
		"beforeUpdateTeam", "afterUpdateTeam",
		"beforeDeleteTeam", "afterDeleteTeam",
		"beforeAddTeamMember", "afterAddTeamMember",
		"beforeRemoveTeamMember", "afterRemoveTeamMember",
	} {
		if !strings.Contains(joinedHooks, expected) {
			t.Fatalf("expected hook %q to have fired; fired hooks: %s", expected, joinedHooks)
		}
	}
}

func TestOfficialBetterAuthClient_EmailOTP(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed, skipping official better-auth/client email-otp test")
	}

	clientScript := filepath.Join("client", "test-email-otp.mjs")
	if _, err := os.Stat(clientScript); err != nil {
		t.Fatalf("client test script not found: %v", err)
	}

	// Step 1: Track dispatched OTPs per email in thread-safe map
	var mu sync.Mutex
	lastOTPs := make(map[string]string)
	var otpSeq int64

	otpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
		SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
			mu.Lock()
			lastOTPs[strings.ToLower(data.Email)] = data.OTP
			mu.Unlock()
			return nil
		},
		GenerateOTP: func(data emailotpconfig.GenerateOTPData, req *http.Request) (string, error) {
			n := atomic.AddInt64(&otpSeq, 1)
			return fmt.Sprintf("GO-%04d", n), nil
		},
		AllowedAttempts: 3,
		StoreOTP: emailotpconfig.StoreOTPConfig{
			Mode: emailotpconfig.StoreOTPEncrypted,
		},
		ResendStrategy: emailotpconfig.ResendStrategyReuse,
		ChangeEmail: emailotpconfig.EmailOTPChangeEmailConfig{
			Enabled: true,
		},
	})

	s := NewServer(t,
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(otpPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Mount test-only endpoint to inspect captured OTPs
	s.Mux.HandleFunc("/test/last-otp", func(w http.ResponseWriter, r *http.Request) {
		email := strings.ToLower(r.URL.Query().Get("email"))
		mu.Lock()
		otp := lastOTPs[email]
		mu.Unlock()
		if otp == "" {
			http.Error(w, "no otp", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"otp": otp})
	})

	// Step 2: Start secondary server configured with strict RateLimit (Max=2 per 60s)
	rlPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
		SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
			return nil
		},
	}, emailotp.WithRateLimit(60*time.Second, 2))
	rls := NewServer(t,
		WithPlugin(rlPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.RateLimit.Enabled = new(true)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// Step 2b: Start server with OverrideDefaultEmailVerification + RequireEmailVerification + AutoSignInAfterVerification
	var ovrMu sync.Mutex
	ovrOTPs := make(map[string]string)
	linkCalls := 0
	otpCalls := 0
	ovrPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
		OverrideDefaultEmailVerification: true,
		SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
			ovrMu.Lock()
			otpCalls++
			ovrOTPs[strings.ToLower(data.Email)] = data.OTP
			ovrMu.Unlock()
			return nil
		},
	})
	ovrServer := NewServer(t,
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(ovrPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
			c.EmailAndPassword.RequireEmailVerification = true
			c.EmailVerification.AutoSignInAfterVerification = true
			c.EmailVerification.SendVerificationEmail = func(data config.EmailVerificationData, r *http.Request) error {
				ovrMu.Lock()
				linkCalls++
				ovrMu.Unlock()
				return nil
			}
		}),
	)
	ovrServer.Mux.HandleFunc("/test/last-otp", func(w http.ResponseWriter, r *http.Request) {
		email := strings.ToLower(r.URL.Query().Get("email"))
		ovrMu.Lock()
		otp := ovrOTPs[email]
		ovrMu.Unlock()
		if otp == "" {
			http.Error(w, "no otp", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"otp": otp})
	})
	ovrServer.Mux.HandleFunc("/test/counts", func(w http.ResponseWriter, r *http.Request) {
		ovrMu.Lock()
		lc, oc := linkCalls, otpCalls
		ovrMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"linkCalls": lc, "otpCalls": oc})
	})

	// Step 3: Run official better-auth/client EmailOTP JS test
	cmd := exec.Command("node", "test-email-otp.mjs")
	cmd.Dir = "client"
	cmd.Env = append(os.Environ(),
		"GOAUTH_URL="+s.URL,
		"GOAUTH_RL_URL="+rls.URL,
		"GOAUTH_OVR_URL="+ovrServer.URL,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official better-auth/client email-otp test failed: %v\nOutput:\n%s", err, string(output))
	}

	t.Logf("official better-auth/client email-otp output:\n%s", string(output))
}
