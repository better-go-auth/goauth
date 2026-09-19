package plugins_test

import (
	"context"
	"testing"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/birukbelay/gocmn/src/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHookRegistry_TriggersAndSubscriptions(t *testing.T) {
	registry := plugins.NewHookRegistry()
	ctx := context.Background()

	var afterUserCreatedCalled bool
	var userDeletedID string
	var userBannedID string
	var sessionCreatedID string
	var sessionRevokedID string
	var activeOrgChangedUser string
	var activeOrgChangedOrg string

	registry.OnAfterUserCreate(func(ctx context.Context, user *models.User) error {
		afterUserCreatedCalled = true
		assert.Equal(t, "user_123", user.ID)
		return nil
	})

	registry.OnUserDeleted(func(ctx context.Context, userID string) error {
		userDeletedID = userID
		return nil
	})

	registry.OnUserBanned(func(ctx context.Context, userID string, reason *string) error {
		userBannedID = userID
		assert.Equal(t, "spamming", *reason)
		return nil
	})

	registry.OnBeforeSessionCreate(func(ctx context.Context, session *models.Session, claims *crypto.CustomClaims) error {
		sessionCreatedID = session.SessionId
		return nil
	})

	registry.OnSessionRevoked(func(ctx context.Context, sessionID string) error {
		sessionRevokedID = sessionID
		return nil
	})

	registry.OnActiveOrgChanged(func(ctx context.Context, userID, newOrgID string) error {
		activeOrgChangedUser = userID
		activeOrgChangedOrg = newOrgID
		return nil
	})

	// 1. Trigger AfterUserCreate
	err := registry.TriggerAfterUserCreate(ctx, &models.User{Base: models.Base{ID: "user_123"}})
	require.NoError(t, err)
	assert.True(t, afterUserCreatedCalled)

	// 2. Trigger UserDeleted
	err = registry.TriggerUserDeleted(ctx, "user_123")
	require.NoError(t, err)
	assert.Equal(t, "user_123", userDeletedID)

	// 3. Trigger UserBanned
	reason := "spamming"
	err = registry.TriggerUserBanned(ctx, "user_123", &reason)
	require.NoError(t, err)
	assert.Equal(t, "user_123", userBannedID)

	// 4. Trigger BeforeSessionCreate
	err = registry.TriggerBeforeSessionCreate(ctx, &models.Session{SessionId: "sess_abc"}, &crypto.CustomClaims{})
	require.NoError(t, err)
	assert.Equal(t, "sess_abc", sessionCreatedID)

	// 5. Trigger SessionRevoked
	err = registry.TriggerSessionRevoked(ctx, "sess_abc")
	require.NoError(t, err)
	assert.Equal(t, "sess_abc", sessionRevokedID)

	// 6. Trigger ActiveOrgChanged
	err = registry.TriggerActiveOrgChanged(ctx, "user_123", "org_xyz")
	require.NoError(t, err)
	assert.Equal(t, "user_123", activeOrgChangedUser)
	assert.Equal(t, "org_xyz", activeOrgChangedOrg)
}

type mockHookService struct {
	plugins.DefaultHookService
	userDeletedCalled bool
	lastUserID        string
}

func (m *mockHookService) UserDeleted(ctx context.Context, userID string) error {
	m.userDeletedCalled = true
	m.lastUserID = userID
	return nil
}

func TestHookRegistry_HookService(t *testing.T) {
	registry := plugins.NewHookRegistry()
	ctx := context.Background()

	svc := &mockHookService{}
	registry.Register(svc)
	// Duplicate registration should be ignored
	registry.Append(svc)

	// Trigger unimplemented method (embedded DefaultHookService returns nil)
	err := registry.TriggerAfterUserCreate(ctx, &models.User{Base: models.Base{ID: "user_456"}})
	require.NoError(t, err)
	assert.False(t, svc.userDeletedCalled)

	// Trigger implemented method
	err = registry.TriggerUserDeleted(ctx, "user_456")
	require.NoError(t, err)
	assert.True(t, svc.userDeletedCalled)
	assert.Equal(t, "user_456", svc.lastUserID)
}

