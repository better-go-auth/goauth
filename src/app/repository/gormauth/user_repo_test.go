package gormauth_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"gorm.io/driver/sqlite"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func ptr[T any](v T) *T {
	return &v
}

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:memdb_%s?mode=memory&cache=shared", uuid.New().String())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Discard,
	})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.User{})
	require.NoError(t, err)

	return db
}

func TestUserRepo_DeleteUser_AnonymizesEmail(t *testing.T) {
	db := setupTestDB(t)
	repo := gormauth.NewUserRepo(db)
	ctx := context.Background()

	originalEmail := "test_anonymize@example.com"
	user := &models.User{
		UserDto: models.UserDto{
			FirstName: "Alice",
			LastName:  "Smith",
			Email:     ptr(originalEmail),
			Role:      enums.User,
		},
	}

	created, err := repo.CreateUser(ctx, user)
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)

	// Verify user can be fetched by ID and email
	found, err := repo.GetUserByID(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, originalEmail, *found.Email)

	foundByEmail, err := repo.GetUserByEmail(ctx, originalEmail)
	require.NoError(t, err)
	require.Equal(t, created.ID, foundByEmail.ID)

	// Soft delete the user
	err = repo.DeleteUser(ctx, created.ID)
	require.NoError(t, err)

	// User should no longer be found by active queries
	_, err = repo.GetUserByID(ctx, created.ID)
	require.Error(t, err)

	_, err = repo.GetUserByEmail(ctx, originalEmail)
	require.Error(t, err)

	// Verify database record has been anonymized and has deleted_at set
	var rawUser models.User
	err = db.Unscoped().Where("id = ?", created.ID).Take(&rawUser).Error
	require.NoError(t, err)
	require.True(t, rawUser.DeletedAt.Valid)
	require.NotNil(t, rawUser.Email)
	require.True(t, strings.HasPrefix(*rawUser.Email, fmt.Sprintf("deleted_%s_", created.ID)))
	require.True(t, strings.HasSuffix(*rawUser.Email, "@deleted.local"))

	// Create another user with the SAME original email - should succeed without unique constraint error
	newUser := &models.User{
		UserDto: models.UserDto{
			FirstName: "Bob",
			LastName:  "Jones",
			Email:     ptr(originalEmail),
			Role:      enums.User,
		},
	}
	newCreated, err := repo.CreateUser(ctx, newUser)
	require.NoError(t, err)
	require.NotEmpty(t, newCreated.ID)
	require.NotEqual(t, created.ID, newCreated.ID)

	// Active GetUserByEmail should now return the newly created user
	activeUser, err := repo.GetUserByEmail(ctx, originalEmail)
	require.NoError(t, err)
	require.Equal(t, newCreated.ID, activeUser.ID)
}
