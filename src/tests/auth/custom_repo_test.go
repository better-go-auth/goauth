package auth_test

import (
	"context"
	"net/http"
	"testing"

	bettergoauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuthRepos implements repo_interfaces.IAuthRepos in memory without GORM.
type mockAuthRepos struct {
	users         map[string]*models.User
	sessions      map[string]*models.Session
	verifications map[string]*models.Verification
	accounts      map[string]*models.Account
}

func newMockAuthRepos() *mockAuthRepos {
	return &mockAuthRepos{
		users:         make(map[string]*models.User),
		sessions:      make(map[string]*models.Session),
		verifications: make(map[string]*models.Verification),
		accounts:      make(map[string]*models.Account),
	}
}

// IUserRepo methods
func (m *mockAuthRepos) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if user.ID == "" {
		user.ID = models.NewID()
	}
	m.users[user.ID] = user
	return user, nil
}
func (m *mockAuthRepos) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}
func (m *mockAuthRepos) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	for _, u := range m.users {
		if u.Email != nil && *u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}
func (m *mockAuthRepos) UpdateUser(ctx context.Context, id string, data map[string]interface{}) (*models.User, error) {
	return m.users[id], nil
}
func (m *mockAuthRepos) DeleteUser(ctx context.Context, id string) error {
	delete(m.users, id)
	return nil
}
func (m *mockAuthRepos) ListUsers(ctx context.Context, filter repo_interfaces.UserFilter, pagi dtos.PaginationInput) ([]models.User, int64, error) {
	var list []models.User
	for _, u := range m.users {
		list = append(list, *u)
	}
	return list, int64(len(list)), nil
}

// IOAuthAccountRepo methods
func (m *mockAuthRepos) CreateAccount(ctx context.Context, account *models.Account) (*models.Account, error) {
	m.accounts[account.ID] = account
	return account, nil
}
func (m *mockAuthRepos) GetAccountByProviderAndAccountID(ctx context.Context, providerID models.Providers, accountID string) (*models.Account, error) {
	return nil, nil
}
func (m *mockAuthRepos) GetAccountByUserAndProvider(ctx context.Context, userID string, providerID models.Providers) (*models.Account, error) {
	return nil, nil
}
func (m *mockAuthRepos) UpdateAccount(ctx context.Context, id string, data map[string]interface{}) (*models.Account, error) {
	return m.accounts[id], nil
}
func (m *mockAuthRepos) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	return nil
}
func (m *mockAuthRepos) ListAccountsByUserID(ctx context.Context, userID string) ([]models.Account, error) {
	return nil, nil
}
func (m *mockAuthRepos) DeleteAccountByUserAndProvider(ctx context.Context, userID, providerID string) error {
	return nil
}

// ISessionRepo methods
func (m *mockAuthRepos) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	m.sessions[session.SessionId] = session
	return session, nil
}
func (m *mockAuthRepos) UpsertSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	m.sessions[session.SessionId] = session
	return session, nil
}
func (m *mockAuthRepos) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	return m.sessions[id], nil
}
func (m *mockAuthRepos) GetSessionBySessionID(ctx context.Context, sessionID string) (*models.Session, error) {
	return m.sessions[sessionID], nil
}
func (m *mockAuthRepos) GetSessionByToken(ctx context.Context, token string) (*models.Session, error) {
	return m.sessions[token], nil
}
func (m *mockAuthRepos) UpdateSession(ctx context.Context, sessionID string, data map[string]interface{}) (*models.Session, error) {
	return m.sessions[sessionID], nil
}
func (m *mockAuthRepos) DeleteSession(ctx context.Context, sessionID string) error {
	delete(m.sessions, sessionID)
	return nil
}
func (m *mockAuthRepos) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	for k, v := range m.sessions {
		if v.UserID == userID {
			delete(m.sessions, k)
		}
	}
	return nil
}
func (m *mockAuthRepos) ListSessionsByUserID(ctx context.Context, userID string) ([]models.Session, error) {
	var list []models.Session
	for _, s := range m.sessions {
		if s.UserID == userID {
			list = append(list, *s)
		}
	}
	return list, nil
}
func (m *mockAuthRepos) ListSessions(ctx context.Context, filter models.SessionFilter, pagi dtos.PaginationInput) ([]models.Session, int64, error) {
	var list []models.Session
	for _, s := range m.sessions {
		list = append(list, *s)
	}
	return list, int64(len(list)), nil
}

// IVerificationRepo methods
func (m *mockAuthRepos) UpsertVerification(ctx context.Context, verification *models.Verification) (*models.Verification, error) {
	m.verifications[verification.Identifier] = verification
	return verification, nil
}
func (m *mockAuthRepos) GetVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose) (*models.Verification, error) {
	full := purpose.Make(identifier)
	return m.verifications[full], nil
}
func (m *mockAuthRepos) DeleteVerification(ctx context.Context, identifier string, purpose models.VerificationPurpose) error {
	full := purpose.Make(identifier)
	delete(m.verifications, full)
	return nil
}
func (m *mockAuthRepos) DeleteExpired(ctx context.Context) error {
	return nil
}

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

	mockRepos := newMockAuthRepos()
	migrator := &noOpMigrator{}
	txMgr := &noOpTxManager{}

	opts := bettergoauth.GoAuthOptions{
		Conn:         nil, // zero GORM dependency!
		Repositories: mockRepos,
		Migrator:     migrator,
		TxManager:    txMgr,
	}
	opts.SessionConfig.AccessSecret = "super-secret-access-key-32-chars-long"

	app, err := bettergoauth.SetupGoAuth(api, opts)
	require.NoError(t, err)
	assert.NotNil(t, app)
	assert.True(t, migrator.migrated, "Custom migrator should be executed")
	assert.NotNil(t, app.IAuthServices)
}
