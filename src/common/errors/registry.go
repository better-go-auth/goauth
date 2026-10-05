package errors

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
)

// WithStatus returns a copy with a different HTTP status; endpoints differ for the same code.
func (e *AuthError) WithStatus(status int) *AuthError {
	c := *e
	c.StatusCode = status
	return &c
}

// WithMessage returns a copy with a custom message and the same code.
func (e *AuthError) WithMessage(message string) *AuthError {
	c := *e
	c.Message = message
	return &c
}

var (
	registryMu sync.RWMutex
	registry   = map[string]*AuthError{}
)

// Err defines and registers an error code with its default HTTP status.
// Registering the same code with a different message panics, as it is a programming error.
func Err(status int, code, message string) *AuthError {
	registryMu.Lock()
	defer registryMu.Unlock()
	if existing, ok := registry[code]; ok {
		if existing.Message != message {
			panic(fmt.Sprintf("errors: code %q already registered with message %q", code, existing.Message))
		}
		return existing
	}
	e := &AuthError{StatusCode: status, Code: RespCode(code), Message: message}
	registry[code] = e
	return e
}

// Register lets plugins add their own codes (better-auth `$ERROR_CODES`), defaulting to 400.
func Register(code, message string) *AuthError {
	return Err(http.StatusBadRequest, code, message)
}

// Lookup returns the registered error for code.
func Lookup(code string) (*AuthError, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	e, ok := registry[code]
	return e, ok
}

// Codes returns all registered codes, sorted.
func Codes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for c := range registry {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
