// Package verifycleanup wraps an IAuthRepos so expired verification rows are deleted when verifications
// are read, like better-auth's internalAdapter.findVerificationValue (unless verification.disableCleanup).
package verifycleanup

import (
	"context"
	"github.com/better-go-auth/goauth/src/common/logger"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/models"
)

// Repos is an IAuthRepos whose FindVerificationValue also purges expired verifications.
type Repos struct {
	repo_interfaces.IAuthRepos
}

// Wrap returns repos with read-time cleanup. Wrapping twice is a no-op.
func Wrap(repos repo_interfaces.IAuthRepos) repo_interfaces.IAuthRepos {
	if repos == nil {
		return nil
	}
	if _, ok := repos.(*Repos); ok {
		return repos
	}
	return &Repos{IAuthRepos: repos}
}

// Unwrap returns the repositories under the cleanup wrapper.
func (r *Repos) Unwrap() repo_interfaces.IAuthRepos { return r.IAuthRepos }

// FindVerificationValue fetches the newest verification for identifier, then deletes every expired
// verification. The row is returned even when it is expired, so callers can still answer "expired".
func (r *Repos) FindVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
	// Step 1: read first, so an expired row can still be reported as expired by the caller
	v, err := r.IAuthRepos.FindVerificationValue(ctx, identifier)
	// Step 2: purge expired rows (better-auth deletes where expiresAt < now on every read)
	if cerr := r.IAuthRepos.DeleteExpiredVerifications(ctx); cerr != nil {
		logger.Warn("goauth: expired verification cleanup failed", "err", cerr)
	}
	return v, err
}
