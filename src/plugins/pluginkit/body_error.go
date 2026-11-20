package pluginkit

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// BodyError is an endpoint error whose JSON body is sent exactly as given, for better-auth endpoints that
// throw `new APIError(status, body)` with a body other than {code, message}: OAuth style
// {error, error_description} (device-authorization) or {message, status, code} (siwe).
// It implements huma.StatusError, so a handler can return it like an *autherr.AuthError.
type BodyError struct {
	// Status is the HTTP status code.
	Status int
	// Body is encoded as the response body (a struct with JSON tags or a map).
	Body any
}

// NewBodyError builds a BodyError.
func NewBodyError(status int, body any) *BodyError { return &BodyError{Status: status, Body: body} }

// Error implements error.
func (e *BodyError) Error() string {
	raw, _ := json.Marshal(e.Body)
	return fmt.Sprintf("[%d %s] %s", e.Status, http.StatusText(e.Status), raw)
}

// GetStatus implements huma.StatusError.
func (e *BodyError) GetStatus() int { return e.Status }

// MarshalJSON encodes Body only.
func (e *BodyError) MarshalJSON() ([]byte, error) { return json.Marshal(e.Body) }
