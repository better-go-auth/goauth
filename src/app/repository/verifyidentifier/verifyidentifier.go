// Package verifyidentifier wraps an IAuthRepos so verification identifiers are stored hashed (or with a custom
// hash), like better-auth's verification.storeIdentifier in internalAdapter: identifiers are processed before
// every write and lookup, and lookups fall back to the plain identifier so rows written before the option was
// enabled keep working.
package verifyidentifier

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
)

// Repos is an IAuthRepos whose verification identifiers follow VerificationOptions.StoreIdentifier.
type Repos struct {
	repo_interfaces.IAuthRepos
	opts config.VerificationOptions
}

// Wrap returns repos with identifier processing, or repos unchanged when every identifier is stored plain.
func Wrap(repos repo_interfaces.IAuthRepos, opts config.VerificationOptions) repo_interfaces.IAuthRepos {
	if repos == nil || !opts.HashesIdentifiers() {
		return repos
	}
	return &Repos{IAuthRepos: repos, opts: opts}
}

// Unwrap returns the repositories under the wrapper.
func (r *Repos) Unwrap() repo_interfaces.IAuthRepos { return r.IAuthRepos }

// stored is better-auth's processIdentifier(identifier, getStorageOption(identifier)); plain reports whether
// the option stores identifiers unchanged (then there is no plain fallback to try).
func (r *Repos) stored(identifier string) (stored string, plain bool, err error) {
	opt := r.opts.IdentifierOption(identifier)
	stored, err = opt.Process(identifier)
	return stored, opt.IsPlain(), err
}

// UpsertVerificationValue writes the verification under its processed identifier (createVerificationValue).
func (r *Repos) UpsertVerificationValue(ctx context.Context, v *models.Verification) (*models.Verification, error) {
	// Step 1: process the identifier on a copy, so the caller's struct keeps the plain value
	stored, _, err := r.stored(v.Identifier)
	if err != nil {
		return nil, err
	}
	row := *v
	row.Identifier = stored
	// Step 2: write
	return r.IAuthRepos.UpsertVerificationValue(ctx, &row)
}

// FindVerificationValue looks the processed identifier up, then the plain one (findVerificationValue).
func (r *Repos) FindVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
	// Step 1: the stored form
	stored, plain, err := r.stored(identifier)
	if err != nil {
		return nil, err
	}
	v, err := r.IAuthRepos.FindVerificationValue(ctx, stored)
	// Step 2: rows written before hashing was enabled
	if !plain && isNotFound(err) {
		return r.IAuthRepos.FindVerificationValue(ctx, identifier)
	}
	return v, err
}

// ConsumeVerificationValue consumes the processed identifier, then the plain one (consumeVerificationValue).
func (r *Repos) ConsumeVerificationValue(ctx context.Context, identifier string) (*models.Verification, error) {
	// Step 1: the stored form
	stored, plain, err := r.stored(identifier)
	if err != nil {
		return nil, err
	}
	v, err := r.IAuthRepos.ConsumeVerificationValue(ctx, stored)
	// Step 2: rows written before hashing was enabled
	if !plain && isNotFound(err) {
		return r.IAuthRepos.ConsumeVerificationValue(ctx, identifier)
	}
	return v, err
}

// DeleteVerificationByIdentifier deletes the rows of the processed identifier (deleteVerificationByIdentifier).
func (r *Repos) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error {
	stored, _, err := r.stored(identifier)
	if err != nil {
		return err
	}
	return r.IAuthRepos.DeleteVerificationByIdentifier(ctx, stored)
}

// isNotFound reports whether err is a repository "not found".
func isNotFound(err error) bool {
	ae := autherr.AsAuthError(err)
	return ae != nil && ae.StatusCode == http.StatusNotFound
}
