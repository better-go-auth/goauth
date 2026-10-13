package auth_test

import (
	"context"
	"net/http"
	"testing"

	bettergoauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/app/repository/memory"
	"github.com/better-go-auth/goauth/src/models"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	"github.com/better-go-auth/goauth/src/plugins/access-token/services"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noOpMigrator struct {
	migrated bool
}

func (n *noOpMigrator) Migrate(ctx context.Context) error {
	n.migrated = true
	return nil
}

type noOpTxManager struct{}

func (n *noOpTxManager) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func TestSetupGoAuth_CustomRepositoriesWithoutGorm(t *testing.T) {
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Test API", "1.0.0"))

	mockRepos := memory.New()
	migrator := &noOpMigrator{}
	txMgr := &noOpTxManager{}

	opts := bettergoauth.GoAuthOptions{
		Conn:         nil, // zero GORM dependency!
		Repositories: mockRepos,
		Migrator:     migrator,
		TxManager:    txMgr,
		Plugins:      []plugin.Plugin{accesstoken.New(accesstokenconfig.DefaultAccessTokenConfig())},
	}
	opts.Secret = "super-secret-access-key-32-chars-long"

	app, err := bettergoauth.SetupGoAuth(api, opts)
	require.NoError(t, err)
	assert.NotNil(t, app)
	assert.NotNil(t, app.Auth)
	assert.NotNil(t, app.Sessions)
	assert.NotNil(t, app.Plugins[accesstoken.PluginID])
}

func TestCustomRepositories_AuthAndProfileFlow(t *testing.T) {
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Test API", "1.0.0"))

	mockRepos := memory.New()
	migrator := &noOpMigrator{}
	txMgr := &noOpTxManager{}

	mockEmail := helpers.NewMockEmailSender()

	opts := bettergoauth.GoAuthOptions{
		Conn:         nil, // zero GORM!
		Repositories: mockRepos,
		Migrator:     migrator,
		TxManager:    txMgr,
	}
	opts.Secret = "super-secret-access-key-32-chars-long"
	opts.EmailVerification.GoAuth.CodeSender = mockEmail
	opts.SetDefaults()

	app, err := bettergoauth.SetupGoAuth(api, opts)
	require.NoError(t, err)

	ctx := context.Background()

	passwords := authcrypto.NewPasswords(opts.AuthConfig)
	// access token services
	aTVfcSvc := services.NewVerificationService(mockRepos, opts.EmailVerification)
	aTsSvc := services.NewSessionService(opts.GoAuth.Session, mockRepos, app.Sessions, nil, app.Hooks)
	aTauthSvc := services.NewAuthService(&opts.GoAuth.Session, app.Auth, aTVfcSvc, aTsSvc, mockRepos, txMgr, passwords, app.Hooks)
	aTprofileSvc := services.NewProfileService(aTVfcSvc, aTsSvc, mockRepos, txMgr, passwords)

	// 1. Register with email
	regResp, err := aTauthSvc.RegisterWithEmail(ctx, models.RegisterClientInput{
		FirstName: "Alice",
		LastName:  "Smith",
		Email:     "alice@example.com",
		Password:  "SecurePassword123!",
	})
	require.NoError(t, err)
	assert.Equal(t, "Alice", regResp.User.Name)
	// assert.Equal(t, "Smith", regResp.User.Name)
	assert.Equal(t, "alice@example.com", regResp.User.Email)
	userID := regResp.User.ID

	// 2. Profile GetProfile
	userProfile, err := aTprofileSvc.GetProfile(ctx, userID)
	require.NoError(t, err)
	assert.NotNil(t, userProfile)
	assert.Equal(t, "Alice", userProfile.FirstName)

	// 3. Profile UpdateProfile
	updatedProfile, err := aTprofileSvc.UpdateProfile(ctx, userID, models.ProfileUpdateDto{
		FirstName: "Alicia",
		LastName:  "Keys",
	})
	require.NoError(t, err)
	assert.NotNil(t, updatedProfile)
	assert.Equal(t, "Alicia", updatedProfile.FirstName)
	assert.Equal(t, "Keys", updatedProfile.LastName)

	// Verify it persists in mock repository
	retrieved, err := mockRepos.FindUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "Alicia", retrieved.FirstName)
	assert.Equal(t, "Keys", retrieved.LastName)
}
