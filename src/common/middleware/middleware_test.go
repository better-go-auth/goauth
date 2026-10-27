package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/common/middleware"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_JWTTokenVerifier(t *testing.T) {
	secret := "test-secret-key-32-chars-long-1234"
	claims := &token.CustomClaims{
		UserID:    "user_1",
		SessionID: "sess_1",
		Role:      "USER",
		Type:      token.TypeAccess,
	}

	tokenStr, err := jwttoken.SignWithExpiry(secret, claims, 15*time.Minute)
	require.NoError(t, err)

	verifier := middleware.NewJWTTokenVerifier(secret)
	verifiedClaims, err := verifier.VerifyToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user_1", verifiedClaims.UserID)

	claims.Type = token.TypeRefresh
	refreshStr, err := jwttoken.SignWithExpiry(secret, claims, 15*time.Minute)
	require.NoError(t, err)
	_, err = verifier.VerifyToken(refreshStr)
	assert.Error(t, err, "a refresh token must not be accepted as an access token")
	assert.Equal(t, "sess_1", verifiedClaims.SessionID)
	assert.Equal(t, "USER", verifiedClaims.Role)
}

func TestMiddleware_KeyValRevocationStore(t *testing.T) {
	memStore, err := memory.NewSecondaryStorage()
	require.NoError(t, err)

	revStore := middleware.NewKeyValRevocationStore(memStore)
	ctx := context.Background()

	revoked, err := revStore.IsRevoked(ctx, "session_123")
	require.NoError(t, err)
	assert.False(t, revoked)

	// Blacklist session
	err = memStore.Set(ctx, sec_storage.RevokedSessionPrefix+"session_123", true, 10*time.Minute)
	require.NoError(t, err)

	revoked, err = revStore.IsRevoked(ctx, "session_123")
	require.NoError(t, err)
	assert.True(t, revoked)
}

type mockSessionClaimsResolver struct {
	claims *token.CustomClaims
	err    error
}

func (m *mockSessionClaimsResolver) ClaimsFromSession(ctx context.Context, bearer, cookieHeader string) (*token.CustomClaims, error) {
	return m.claims, m.err
}

func TestAuthMiddleware_SessionResolution(t *testing.T) {
	memStore, err := memory.NewSecondaryStorage()
	require.NoError(t, err)
	revStore := middleware.NewKeyValRevocationStore(memStore)

	mdl := middleware.NewAuthMiddleware(revStore, nil)
	resolver := &mockSessionClaimsResolver{
		claims: &token.CustomClaims{
			UserID:    "user_cookie_1",
			SessionID: "sess_cookie_1",
			Role:      "USER",
		},
	}
	mdl.WithSessions(resolver)
	assert.NotNil(t, mdl)
}

func TestAuthMiddleware_AuthenticateOptional(t *testing.T) {
	resolver := &mockSessionClaimsResolver{
		claims: &token.CustomClaims{
			UserID:    "user_opt_123",
			SessionID: "sess_opt_123",
			Role:      "USER",
		},
	}

	mdl := middleware.NewAuthMiddleware(nil, nil)
	mdl.WithSessions(resolver)

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Optional Test API", "1.0.0"))

	type EchoInput struct {
		Authorization string `header:"Authorization"`
	}
	type EchoOutput struct {
		Body struct {
			Authenticated bool   `json:"authenticated"`
			UserID        string `json:"userId"`
		}
	}

	huma.Register(api, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/optional",
		Middlewares: huma.Middlewares{mdl.AuthenticateOptional()},
	}, func(ctx context.Context, input *EchoInput) (*EchoOutput, error) {
		out := &EchoOutput{}
		if uid, ok := ctx.Value(consts.CTXUser_ID.Str()).(string); ok && uid != "" {
			out.Body.Authenticated = true
			out.Body.UserID = uid
		}
		return out, nil
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// 1. No credentials at all -> passes through unauthenticated (200 OK, authenticated=false)
	req1, _ := http.NewRequest(http.MethodGet, server.URL+"/api/optional", nil)
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	_ = resp1.Body.Close()

	// 2. 3-segment access token JWT -> passes through unauthenticated so downstream access token middleware can handle it
	req2, _ := http.NewRequest(http.MethodGet, server.URL+"/api/optional", nil)
	req2.Header.Set("Authorization", "Bearer header.payload.signature")
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	_ = resp2.Body.Close()

	// 3. Valid session bearer token -> authenticates user and populates context (200 OK)
	req3, _ := http.NewRequest(http.MethodGet, server.URL+"/api/optional", nil)
	req3.Header.Set("Authorization", "Bearer valid_session_token_without_two_dots")
	resp3, err := http.DefaultClient.Do(req3)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp3.StatusCode)
	_ = resp3.Body.Close()
}

func TestAuthMiddleware_AuthenticateOptional_RequireAuth(t *testing.T) {
	resolver := &mockSessionClaimsResolver{
		claims: &token.CustomClaims{
			UserID:    "user_req_123",
			SessionID: "sess_req_123",
			Role:      "USER",
		},
	}

	mdl := middleware.NewAuthMiddleware(nil, nil)
	mdl.WithSessions(resolver)

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("RequireAuth Test API", "1.0.0"))

	type EchoInput struct {
		Authorization string `header:"Authorization"`
	}
	type EchoOutput struct {
		Body struct {
			Authenticated bool   `json:"authenticated"`
			UserID        string `json:"userId"`
		}
	}

	huma.Register(api, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/required",
		Middlewares: huma.Middlewares{mdl.AuthenticateOptional(middleware.AuthOpt{RequireAuth: true})},
	}, func(ctx context.Context, input *EchoInput) (*EchoOutput, error) {
		out := &EchoOutput{}
		if uid, ok := ctx.Value(consts.CTXUser_ID.Str()).(string); ok && uid != "" {
			out.Body.Authenticated = true
			out.Body.UserID = uid
		}
		return out, nil
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// 1. No credentials -> 401 Unauthorized
	req1, _ := http.NewRequest(http.MethodGet, server.URL+"/api/required", nil)
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp1.StatusCode)
	_ = resp1.Body.Close()

	// 2. Valid session bearer token -> 200 OK
	req2, _ := http.NewRequest(http.MethodGet, server.URL+"/api/required", nil)
	req2.Header.Set("Authorization", "Bearer valid_session_token")
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	_ = resp2.Body.Close()

	// 3. 3-segment access token JWT -> passes through (so downstream access token plugin can authenticate it)
	req3, _ := http.NewRequest(http.MethodGet, server.URL+"/api/required", nil)
	req3.Header.Set("Authorization", "Bearer header.payload.signature")
	resp3, err := http.DefaultClient.Do(req3)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp3.StatusCode)
	_ = resp3.Body.Close()
}
