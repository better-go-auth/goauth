// Package repotest holds the contract every repo_interfaces.IAuthRepos implementation must pass.
package repotest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/stretchr/testify/require"
)

// Factory returns fresh, empty repositories for one subtest.
type Factory func(t *testing.T) repo_interfaces.IAuthRepos

// Run executes the auth repository contract against the implementation built by newRepos.
func Run(t *testing.T, newRepos Factory) {
	t.Run("users", func(t *testing.T) { testUsers(t, newRepos(t)) })
	t.Run("list users", func(t *testing.T) { testListUsers(t, newRepos(t)) })
	t.Run("sessions", func(t *testing.T) { testSessions(t, newRepos(t)) })
	t.Run("session queries", func(t *testing.T) { testSessionQueries(t, newRepos(t)) })
	t.Run("accounts", func(t *testing.T) { testAccounts(t, newRepos(t)) })
	t.Run("verifications", func(t *testing.T) { testVerifications(t, newRepos(t)) })
}

func newUser(email string) *models.User {
	return &models.User{UserDto: models.UserDto{Name: "Test User", Email: email, Role: enums.User}}
}

func mustCreateUser(t *testing.T, r repo_interfaces.IAuthRepos, email string) *models.User {
	t.Helper()
	u, err := r.CreateUser(context.Background(), newUser(email))
	require.NoError(t, err)
	require.NotEmpty(t, u.ID)
	return u
}

func testUsers(t *testing.T, r repo_interfaces.IAuthRepos) {
	ctx := context.Background()
	u := mustCreateUser(t, r, "Alice@Example.com")
	require.Equal(t, "alice@example.com", u.Email, "emails are stored lowercased")
	require.False(t, u.CreatedAt.IsZero())

	got, err := r.FindUserByID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, "Test User", got.Name)

	got, err = r.FindUserByEmail(ctx, "ALICE@example.com")
	require.NoError(t, err, "email lookup is case-insensitive")
	require.Equal(t, u.ID, got.ID)

	_, err = r.CreateUser(ctx, newUser("alice@example.com"))
	require.Error(t, err, "emails are unique")

	for _, empty := range []func() (*models.User, error){
		func() (*models.User, error) { return r.FindUserByID(ctx, "") },
		func() (*models.User, error) { return r.FindUserByEmail(ctx, "") },
		func() (*models.User, error) { return r.FindUserByID(ctx, "missing") },
	} {
		got, err := empty()
		require.Error(t, err)
		require.Nil(t, got)
	}

	updated, err := r.UpdateUser(ctx, u.ID, map[string]interface{}{
		"Name": "Alice", "EmailVerified": true, "Image": "https://img", "BanReason": nil,
	})
	require.NoError(t, err)
	require.Equal(t, "Alice", updated.Name)
	require.True(t, updated.EmailVerified)
	require.NotNil(t, updated.Image)
	require.Equal(t, "https://img", *updated.Image)

	_, err = r.UpdateUser(ctx, "missing", map[string]interface{}{"Name": "x"})
	require.Error(t, err)

	require.NoError(t, r.DeleteUser(ctx, u.ID))
	_, err = r.FindUserByID(ctx, u.ID)
	require.Error(t, err, "deleted users are not found")
	_, err = r.FindUserByEmail(ctx, "alice@example.com")
	require.Error(t, err)
	mustCreateUser(t, r, "alice@example.com") // a deleted user's email is free again
}

func testListUsers(t *testing.T, r repo_interfaces.IAuthRepos) {
	ctx := context.Background()
	for i, email := range []string{"a@x.com", "b@x.com", "c@y.com"} {
		u := mustCreateUser(t, r, email)
		if i == 2 {
			_, err := r.UpdateUser(ctx, u.ID, map[string]interface{}{"Role": enums.Admin, "Banned": true})
			require.NoError(t, err)
		}
		time.Sleep(2 * time.Millisecond) // distinct createdAt for ordering
	}

	all, total, err := r.ListUsers(ctx, repo_interfaces.UserFilter{}, dtos.PaginationInput{SortBy: "email", SortDir: "asc"})
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Equal(t, []string{"a@x.com", "b@x.com", "c@y.com"}, emails(all))

	pageTwo, total, err := r.ListUsers(ctx, repo_interfaces.UserFilter{}, dtos.PaginationInput{Limit: 2, Page: 2, SortBy: "email", SortDir: "asc"})
	require.NoError(t, err)
	require.EqualValues(t, 3, total, "total ignores pagination")
	require.Equal(t, []string{"c@y.com"}, emails(pageTwo))

	newestFirst, _, err := r.ListUsers(ctx, repo_interfaces.UserFilter{}, dtos.PaginationInput{})
	require.NoError(t, err)
	require.Equal(t, "c@y.com", newestFirst[0].Email, "default order is createdAt desc")

	domain, role, banned := "X.COM", enums.Admin.S(), true
	byEmail, total, err := r.ListUsers(ctx, repo_interfaces.UserFilter{Email: &domain}, dtos.PaginationInput{})
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, byEmail, 2)
	byRole, _, err := r.ListUsers(ctx, repo_interfaces.UserFilter{Role: &role, Banned: &banned}, dtos.PaginationInput{})
	require.NoError(t, err)
	require.Equal(t, []string{"c@y.com"}, emails(byRole))

	field, value := "email", "@y."
	searched, _, err := r.ListUsers(ctx, repo_interfaces.UserFilter{SearchField: &field, SearchValue: &value}, dtos.PaginationInput{})
	require.NoError(t, err)
	require.Equal(t, []string{"c@y.com"}, emails(searched))

	bad := "password"
	_, _, err = r.ListUsers(ctx, repo_interfaces.UserFilter{SearchField: &bad, SearchValue: &value}, dtos.PaginationInput{})
	require.Error(t, err, "only allow-listed fields can be searched")
	_, _, err = r.ListUsers(ctx, repo_interfaces.UserFilter{}, dtos.PaginationInput{SortBy: "password"})
	require.Error(t, err, "only allow-listed fields can be sorted")
}

func emails(users []models.User) []string {
	out := make([]string, len(users))
	for i, u := range users {
		out[i] = u.Email
	}
	return out
}

func newSession(userID, token string, expiresIn time.Duration) *models.Session {
	return &models.Session{UserID: userID, Token: token, ExpiresAt: time.Now().UTC().Add(expiresIn)}
}

func testSessions(t *testing.T, r repo_interfaces.IAuthRepos) {
	ctx := context.Background()
	u := mustCreateUser(t, r, "s@example.com")

	s, err := r.CreateSession(ctx, newSession(u.ID, "token-a", time.Hour))
	require.NoError(t, err)
	require.NotEmpty(t, s.ID)

	_, err = r.CreateSession(ctx, newSession(u.ID, "token-a", time.Hour))
	require.Error(t, err, "tokens are unique")

	got, err := r.FindSession(ctx, "token-a")
	require.NoError(t, err)
	require.Equal(t, s.ID, got.ID)
	got, err = r.FindSessionByID(ctx, s.ID)
	require.NoError(t, err)
	require.Equal(t, "token-a", got.Token)

	for _, empty := range []func() (*models.Session, error){
		func() (*models.Session, error) { return r.FindSession(ctx, "") },
		func() (*models.Session, error) { return r.FindSessionByID(ctx, "") },
		func() (*models.Session, error) { return r.FindSession(ctx, "missing") },
	} {
		got, err := empty()
		require.Error(t, err, "an empty or unknown key must match nothing")
		require.Nil(t, got)
	}

	later := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	updated, err := r.UpdateSession(ctx, s.ID, map[string]interface{}{"ExpiresAt": later, "IPAddress": "1.2.3.4"})
	require.NoError(t, err)
	require.WithinDuration(t, later, updated.ExpiresAt, time.Second)
	require.Equal(t, "1.2.3.4", *updated.IPAddress)
	_, err = r.UpdateSession(ctx, "missing", map[string]interface{}{"ExpiresAt": later})
	require.Error(t, err)

	upsert := newSession(u.ID, "token-b", time.Hour)
	upsert.ID = "legacy-sid"
	_, err = r.UpsertSession(ctx, upsert)
	require.NoError(t, err)
	upsert.Token = "token-c"
	_, err = r.UpsertSession(ctx, upsert)
	require.NoError(t, err, "upsert on an existing id updates it")
	got, err = r.FindSessionByID(ctx, "legacy-sid")
	require.NoError(t, err)
	require.Equal(t, "token-c", got.Token)

	require.NoError(t, r.DeleteSession(ctx, "token-a"))
	_, err = r.FindSession(ctx, "token-a")
	require.Error(t, err)
	require.NoError(t, r.DeleteSessionByID(ctx, "legacy-sid"))
	_, err = r.FindSessionByID(ctx, "legacy-sid")
	require.Error(t, err)
}

func testSessionQueries(t *testing.T, r repo_interfaces.IAuthRepos) {
	ctx := context.Background()
	alice := mustCreateUser(t, r, "alice@q.com")
	bob := mustCreateUser(t, r, "bob@q.com")
	for i, tok := range []string{"a1", "a2", "a3"} {
		expires := time.Hour
		if i == 0 {
			expires = -time.Hour
		}
		_, err := r.CreateSession(ctx, newSession(alice.ID, tok, expires))
		require.NoError(t, err)
	}
	_, err := r.CreateSession(ctx, newSession(bob.ID, "b1", time.Hour))
	require.NoError(t, err)

	list, err := r.ListSessions(ctx, alice.ID)
	require.NoError(t, err)
	require.Len(t, list, 3, "ListSessions includes expired sessions")
	list, err = r.ListSessions(ctx, "")
	require.NoError(t, err)
	require.Empty(t, list)

	pageOne, total, err := r.QuerySessions(ctx, models.SessionFilter{UserId: alice.ID}, dtos.PaginationInput{Limit: 2, Page: 1})
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, pageOne, 2)

	require.NoError(t, r.DeleteExpiredSessions(ctx))
	list, _ = r.ListSessions(ctx, alice.ID)
	require.Len(t, list, 2)

	require.NoError(t, r.DeleteUserSessions(ctx, ""))
	list, _ = r.ListSessions(ctx, bob.ID)
	require.Len(t, list, 1, "an empty user id deletes nothing")
	require.NoError(t, r.DeleteUserSessions(ctx, alice.ID))
	list, _ = r.ListSessions(ctx, alice.ID)
	require.Empty(t, list)
	list, _ = r.ListSessions(ctx, bob.ID)
	require.Len(t, list, 1, "other users' sessions are kept")
}

func testAccounts(t *testing.T, r repo_interfaces.IAuthRepos) {
	ctx := context.Background()
	u := mustCreateUser(t, r, "acc@example.com")
	hash := "scrypt-hash"
	cred, err := r.CreateAccount(ctx, &models.Account{UserID: u.ID, AccountID: u.ID, ProviderID: models.ProvCredential, Password: &hash})
	require.NoError(t, err)
	_, err = r.CreateAccount(ctx, &models.Account{UserID: u.ID, AccountID: "gh-1", ProviderID: models.ProvGithub})
	require.NoError(t, err)

	got, err := r.FindAccountByProviderID(ctx, models.ProvGithub, "gh-1")
	require.NoError(t, err)
	require.Equal(t, u.ID, got.UserID)
	got, err = r.FindAccountByUserAndProvider(ctx, u.ID, models.ProvCredential)
	require.NoError(t, err)
	require.Equal(t, cred.ID, got.ID)

	_, err = r.FindAccountByProviderID(ctx, models.ProvGithub, "")
	require.Error(t, err)
	_, err = r.FindAccountByUserAndProvider(ctx, "", models.ProvCredential)
	require.Error(t, err)

	updated, err := r.UpdateAccount(ctx, cred.ID, map[string]interface{}{"Password": "new-hash"})
	require.NoError(t, err)
	require.Equal(t, "new-hash", *updated.Password)

	all, err := r.FindAccounts(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, all, 2)

	require.NoError(t, r.DeleteAccountByUserAndProvider(ctx, u.ID, string(models.ProvGithub)))
	all, _ = r.FindAccounts(ctx, u.ID)
	require.Len(t, all, 1)

	other, err := r.CreateAccount(ctx, &models.Account{UserID: u.ID, AccountID: "gh-2", ProviderID: models.ProvGithub})
	require.NoError(t, err)
	_, err = r.CreateAccount(ctx, &models.Account{UserID: u.ID, AccountID: "gh-3", ProviderID: models.ProvGithub})
	require.NoError(t, err)
	require.NoError(t, r.DeleteAccount(ctx, other.ID))
	all, _ = r.FindAccounts(ctx, u.ID)
	require.Len(t, all, 2, "DeleteAccount removes only that account")
	require.NoError(t, r.DeleteAccountByUserAndProvider(ctx, u.ID, string(models.ProvGithub)))
	all, _ = r.FindAccounts(ctx, u.ID)
	require.Len(t, all, 1)
	require.NoError(t, r.DeleteAccounts(ctx, ""))
	all, _ = r.FindAccounts(ctx, u.ID)
	require.Len(t, all, 1, "an empty user id deletes nothing")
	require.NoError(t, r.DeleteAccounts(ctx, u.ID))
	all, _ = r.FindAccounts(ctx, u.ID)
	require.Empty(t, all)
}

func testVerifications(t *testing.T, r repo_interfaces.IAuthRepos) {
	ctx := context.Background()
	id := "email-verification:v@example.com"
	_, err := r.UpsertVerificationValue(ctx, &models.Verification{Identifier: id, Value: "first", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	_, err = r.UpsertVerificationValue(ctx, &models.Verification{Identifier: id, Value: "second", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)

	got, err := r.FindVerificationValue(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "second", got.Value, "upsert replaces the previous value")

	_, err = r.FindVerificationValue(ctx, "")
	require.Error(t, err)

	expired := "password-reset:" + strings.Repeat("x", 3)
	_, err = r.UpsertVerificationValue(ctx, &models.Verification{Identifier: expired, Value: "old", ExpiresAt: time.Now().Add(-time.Hour)})
	require.NoError(t, err)
	require.NoError(t, r.DeleteExpiredVerifications(ctx))
	_, err = r.FindVerificationValue(ctx, expired)
	require.Error(t, err)
	_, err = r.FindVerificationValue(ctx, id)
	require.NoError(t, err, "unexpired verifications are kept")

	require.NoError(t, r.DeleteVerificationByIdentifier(ctx, id))
	_, err = r.FindVerificationValue(ctx, id)
	require.Error(t, err)

	consume := "reset-password:tok"
	_, err = r.UpsertVerificationValue(ctx, &models.Verification{Identifier: consume, Value: "user-1", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	got, err = r.ConsumeVerificationValue(ctx, consume)
	require.NoError(t, err)
	require.Equal(t, "user-1", got.Value)
	_, err = r.ConsumeVerificationValue(ctx, consume)
	require.Error(t, err, "a verification can be consumed once")
	_, err = r.UpsertVerificationValue(ctx, &models.Verification{Identifier: consume, Value: "user-1", ExpiresAt: time.Now().Add(-time.Minute)})
	require.NoError(t, err)
	_, err = r.ConsumeVerificationValue(ctx, consume)
	require.Error(t, err, "expired verifications are not returned")
	_, err = r.FindVerificationValue(ctx, consume)
	require.Error(t, err, "consuming an expired verification still deletes it")
	_, err = r.ConsumeVerificationValue(ctx, "")
	require.Error(t, err)

	for _, v := range []models.Verification{
		{Identifier: "reset-password:a", Value: "user-1"},
		{Identifier: "reset-password:b", Value: "user-1"},
		{Identifier: "reset-password:c", Value: "user-2"},
		{Identifier: "delete-account-d", Value: "user-1"},
	} {
		v.ExpiresAt = time.Now().Add(time.Hour)
		_, err = r.UpsertVerificationValue(ctx, &v)
		require.NoError(t, err)
	}
	require.NoError(t, r.DeleteVerificationsByValue(ctx, "reset-password:", ""), "an empty value deletes nothing")
	require.NoError(t, r.DeleteVerificationsByValue(ctx, "reset-password:", "user-1"))
	for id, kept := range map[string]bool{"reset-password:a": false, "reset-password:b": false, "reset-password:c": true, "delete-account-d": true} {
		_, err = r.FindVerificationValue(ctx, id)
		require.Equal(t, kept, err == nil, id)
	}
}
