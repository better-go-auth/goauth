// Package compat holds the wire-format primitives shared by better-auth compatible endpoints.
package compat

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
)

// APIError is serialised as better-auth's error body: {"code": "...", "message": "..."}.
// It implements huma.StatusError so handlers can return it directly.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string  { return e.Code + ": " + e.Message }
func (e *APIError) GetStatus() int { return e.Status }

// WithStatus returns a copy with a different HTTP status; endpoints differ for the same code.
func (e *APIError) WithStatus(status int) *APIError {
	c := *e
	c.Status = status
	return &c
}

// WithMessage returns a copy with a custom message and the same code.
func (e *APIError) WithMessage(message string) *APIError {
	c := *e
	c.Message = message
	return &c
}

// Is matches errors by code so copies made by WithStatus/WithMessage still compare equal.
func (e *APIError) Is(target error) bool {
	t, ok := target.(*APIError)
	return ok && t.Code == e.Code
}

var (
	registryMu sync.RWMutex
	registry   = map[string]*APIError{}
)

// Err defines and registers an error code with its default HTTP status.
// Registering the same code with a different message panics, as it is a programming error.
func Err(status int, code, message string) *APIError {
	registryMu.Lock()
	defer registryMu.Unlock()
	if existing, ok := registry[code]; ok {
		if existing.Message != message {
			panic(fmt.Sprintf("compat: error code %q already registered with message %q", code, existing.Message))
		}
		return existing
	}
	e := &APIError{Status: status, Code: code, Message: message}
	registry[code] = e
	return e
}

// Register lets plugins add their own codes (better-auth `$ERROR_CODES`), defaulting to 400.
func Register(code, message string) *APIError {
	return Err(http.StatusBadRequest, code, message)
}

// Lookup returns the registered error for code.
func Lookup(code string) (*APIError, bool) {
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
