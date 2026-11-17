package test

import (
	"net/http"
	"testing"

	mlconfig "github.com/better-go-auth/goauth/src/plugins/magic-link/config"
)

// TestVerifyMissingTokenIsValidationError checks a missing query parameter answers like better-auth's zod
// validation: 400 {"code":"VALIDATION_ERROR"}.
func TestVerifyMissingTokenIsValidationError(t *testing.T) {
	e := newEnv(t, mlconfig.MagicLinkConfig{}, nil)
	expectCode(t, e.s.Get(t, "/api/auth/magic-link/verify"), http.StatusBadRequest, "VALIDATION_ERROR")
}
