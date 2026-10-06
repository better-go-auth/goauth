package auth_test

import (
	"context"
	"net/http"
	"testing"

	bettergoauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/app/core/profile"
	"github.com/better-go-auth/goauth/src/app/core/session"
	"github.com/better-go-auth/goauth/src/app/core/verification"
	"github.com/better-go-auth/goauth/src/app/repository/memory"
	"github.com/better-go-auth/goauth/src/models"
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
	}
	opts.Secret = "super-secret-access-key-32-chars-long"

	app, err := bettergoauth.SetupGoAuth(api, opts)
	require.NoError(t, err)
	assert.NotNil(t, app)
	assert.True(t, migrator.migrated, "Custom migrator should be executed")
	assert.NotNil(t, app.IAuthServices)
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

	vSvc := verification.NewVerificationServiceWithRepo(mockRepos, opts.EmailVerification)
	sSvc := session.NewServiceWithRepo(opts.GoAuth.Session, mockRepos, nil, app.Hooks)
	authSvc := auth.NewAuthService(&opts.GoAuth.Session, app.Provider, vSvc, sSvc, mockRepos, app.Hooks)
	profileSvc := profile.NewProfileServH(app.Provider, vSvc, sSvc, mockRepos)

	// 1. Register with email
	regResp, err := authSvc.RegisterWithEmail(ctx, models.RegisterClientInput{
		FirstName: "Alice",
		LastName:  "Smith",
		Email:     "alice@example.com",
		Password:  "SecurePassword123!",
	})
	require.NoError(t, err)
	assert.Equal(t, "Alice", regResp.Body.FirstName)
	assert.Equal(t, "Smith", regResp.Body.LastName)
	assert.Equal(t, "alice@example.com", regResp.Body.Email)
	userID := regResp.Body.ID

	// 2. Profile GetProfile
	userProfile, err := profileSvc.GetProfile(ctx, userID)
	require.NoError(t, err)
	assert.NotNil(t, userProfile)
	assert.Equal(t, "Alice", userProfile.FirstName)

	// 3. Profile UpdateProfile
	updatedProfile, err := profileSvc.UpdateProfile(ctx, userID, models.ProfileUpdateDto{
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
