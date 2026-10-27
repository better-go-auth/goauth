package org_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-go-auth/goauth/src/common/consts"
	coremodels "github.com/better-go-auth/goauth/src/models"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	orgmiddleware "github.com/better-go-auth/goauth/src/plugins/org/middleware"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	pluginrepos "github.com/better-go-auth/goauth/src/plugins/org/repository"
	orgrepo "github.com/better-go-auth/goauth/src/plugins/org/repository/gorm"
	orgsvc "github.com/better-go-auth/goauth/src/plugins/org/services"
	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestOrgMiddleware_Authorization tests the exported Huma and net/http authorization middlewares.
func TestOrgMiddleware_Authorization(t *testing.T) {
	helpers.RunForEachDB(t, func(t *testing.T, db *gorm.DB, dbType helpers.DatabaseType) {
		// Step 1: Migrate tables for the database engine
		helpers.RunMigrations(t, db)

		// Step 2: Seed Owner User and Organization
		ownerID := uuid.New().String()
		now := coremodels.TimeNow()
		owner := &coremodels.User{
			Base: coremodels.Base{ID: ownerID, CreatedAt: now, UpdatedAt: now},
			UserDto: coremodels.UserDto{
				Name:  "Test Owner",
				Email: "owner-mw-" + string(dbType) + "-" + uuid.New().String()[:8] + "@example.com",
			},
		}
		require.NoError(t, db.Create(owner).Error)

		orgID := uuid.New().String()
		testOrg := &orgmodels.Organization{
			Base:      coremodels.Base{ID: orgID, CreatedAt: now, UpdatedAt: now},
			Name:      "Middleware Corp " + string(dbType),
			Slug:      "mw-" + string(dbType) + "-" + uuid.New().String()[:8],
			CreatedBy: ownerID,
		}
		require.NoError(t, db.Create(testOrg).Error)

		member := &orgmodels.Member{
			Base:           coremodels.Base{ID: uuid.New().String(), CreatedAt: now, UpdatedAt: now},
			OrganizationID: orgID,
			UserID:         ownerID,
			Role:           orgmodels.OrgRoleOwner,
		}
		require.NoError(t, db.Create(member).Error)

		cfg := orgconfig.OrgConfig{
			DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{
				Enabled:    true,
				AuthMethod: orgconfig.AuthMethodBoth,
			},
		}

		svc := orgsvc.New(
			orgrepo.NewOrgRepo(db),
			orgrepo.NewMemberRepo(db),
			orgrepo.NewInvitationRepo(db),
			nil,
			nil,
			nil,
		)
		svc.Config = cfg
		svc.SetRepositories(pluginrepos.OrgRepositories{
			ITeamRepo:             orgrepo.NewTeamRepo(db),
			ITeamMemberRepo:       orgrepo.NewTeamMemberRepo(db),
			IOrganizationRoleRepo: orgrepo.NewOrganizationRoleRepo(db),
		})

		ctx := context.Background()

		// Create dynamic role with ops and permission
		_, err := svc.CreateRoleWithOps(
			ctx,
			orgID,
			"editor",
			orgmodels.Permission{"post": []string{"read", "edit"}},
			orgmodels.Operations{"publishPost"},
			ownerID,
		)
		require.NoError(t, err)

		orgMW := orgmiddleware.New(svc)

		t.Run("HTTP RequireOperation allows permitted operation", func(t *testing.T) {
			handler := orgMW.HTTPRequireOperation("publishPost")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			}))

			// Request with claims containing ActiveOrgId and ActiveOrgRole
			req := httptest.NewRequest("GET", "/posts/publish", nil)
			req = req.WithContext(context.WithValue(req.Context(), consts.CtxClaims.Str(), token.CustomClaims{
				UserID:        "user-1",
				ActiveOrgId:   orgID,
				ActiveOrgRole: "editor",
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)
		})

		t.Run("HTTP RequireOperation rejects unpermitted operation", func(t *testing.T) {
			handler := orgMW.HTTPRequireOperation("deletePost")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("POST", "/posts/delete", nil)
			req = req.WithContext(context.WithValue(req.Context(), consts.CtxClaims.Str(), token.CustomClaims{
				UserID:        "user-1",
				ActiveOrgId:   orgID,
				ActiveOrgRole: "editor",
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusForbidden, rec.Code)
		})

		t.Run("HTTP RequirePermission allows permitted action", func(t *testing.T) {
			handler := orgMW.HTTPRequirePermission("post", "edit")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("PUT", "/posts/1", nil)
			req = req.WithContext(context.WithValue(req.Context(), consts.CtxClaims.Str(), token.CustomClaims{
				UserID:        "user-1",
				ActiveOrgId:   orgID,
				ActiveOrgRole: "editor",
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)
		})

		t.Run("HTTP RequirePermission rejects unauthenticated request", func(t *testing.T) {
			handler := orgMW.HTTPRequirePermission("post", "edit")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("PUT", "/posts/1", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
		})

		t.Run("Huma middleware integration", func(t *testing.T) {
			router := chi.NewRouter()
			api := humachi.New(router, huma.DefaultConfig("Test API", "1.0.0"))

			// Register route with Huma RequireOperation middleware
			huma.Register(api, huma.Operation{
				OperationID: "test-publish",
				Method:      http.MethodPost,
				Path:        "/huma/publish",
				Middlewares: huma.Middlewares{
					orgMW.RequireOperation("publishPost"),
				},
			}, func(ctx context.Context, input *struct{}) (*struct{ Body string }, error) {
				return &struct{ Body string }{Body: "published"}, nil
			})

			// 1. Authorized call
			req := httptest.NewRequest("POST", "/huma/publish", nil)
			req = req.WithContext(context.WithValue(req.Context(), consts.CtxClaims.Str(), token.CustomClaims{
				UserID:        "user-1",
				ActiveOrgId:   orgID,
				ActiveOrgRole: "editor",
			}))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)

			// 2. Unauthorized role
			reqDenied := httptest.NewRequest("POST", "/huma/publish", nil)
			reqDenied = reqDenied.WithContext(context.WithValue(reqDenied.Context(), consts.CtxClaims.Str(), token.CustomClaims{
				UserID:        "user-2",
				ActiveOrgId:   orgID,
				ActiveOrgRole: "viewer", // viewer doesn't have publishPost
			}))
			recDenied := httptest.NewRecorder()
			router.ServeHTTP(recDenied, reqDenied)
			require.Equal(t, http.StatusForbidden, recDenied.Code)
		})
	})
}
