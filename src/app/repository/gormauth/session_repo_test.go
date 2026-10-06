package gormauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/stretchr/testify/require"
)

// Struct conditions skip zero values unless the field is named, so an empty key must match nothing, not every row.
func TestSessionRepo_EmptyKeysMatchNothing(t *testing.T) {
	db := setupTestDB(t)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	repo := gormauth.NewSessionRepo(db)
	ctx := context.Background()

	_, err := repo.CreateSession(ctx, &models.Session{Token: "tok", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)

	got, err := repo.FindSession(ctx, "")
	require.Error(t, err)
	require.Nil(t, got)
	got, err = repo.FindSessionByID(ctx, "")
	require.Error(t, err)
	require.Nil(t, got)

	require.NoError(t, repo.DeleteUserSessions(ctx, ""))
	rows, err := repo.ListSessions(ctx, "u1")
	require.NoError(t, err)
	require.Len(t, rows, 1)

	got, err = repo.FindSession(ctx, "tok")
	require.NoError(t, err)
	require.Equal(t, "u1", got.UserID)
}
