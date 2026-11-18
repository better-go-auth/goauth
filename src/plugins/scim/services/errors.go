package services

import (
	"net/http"
	"strconv"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// SCIMErrorSchema is the schema URN of SCIM errors (RFC 7644 §3.12).
const SCIMErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"

// SCIMError is better-auth's SCIMAPIError: the RFC 7644 error body
// {"schemas": [...Error], "status": "404", "detail": "...", "scimType": "..."} with the HTTP status.
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	SCIMType string   `json:"scimType,omitempty"`
	code     int
}

// Error returns the detail.
func (e *SCIMError) Error() string { return e.Detail }

// GetStatus returns the HTTP status (huma.StatusError).
func (e *SCIMError) GetStatus() int { return e.code }

// NewSCIMError builds a SCIM error.
func NewSCIMError(status int, detail, scimType string) *SCIMError {
	return &SCIMError{Schemas: []string{SCIMErrorSchema}, Status: strconv.Itoa(status), Detail: detail, SCIMType: scimType, code: status}
}

// apiError is `new APIError(status, { message })` (no code).
func apiError(status int, message string) *autherr.AuthError {
	return pluginkit.NewError(status, "", message)
}

// SCIM errors of the user endpoints.
var (
	ErrTokenRequired    = NewSCIMError(http.StatusUnauthorized, "SCIM token is required", "")
	ErrInvalidToken     = NewSCIMError(http.StatusUnauthorized, "Invalid SCIM token", "")
	ErrUserNotFound     = NewSCIMError(http.StatusNotFound, "User not found", "")
	ErrUserExists       = NewSCIMError(http.StatusConflict, "User already exists", "uniqueness")
	ErrNoValidPatch     = NewSCIMError(http.StatusBadRequest, "No valid fields to update", "")
	ErrSchemaNotFound   = NewSCIMError(http.StatusNotFound, "Schema not found", "")
	ErrResourceNotFound = NewSCIMError(http.StatusNotFound, "Resource type not found", "")
)

// API errors of the management endpoints (better-auth's APIError with a message).
var (
	ErrForbiddenCharacters  = apiError(http.StatusBadRequest, "Provider id contains forbidden characters")
	ErrBuiltInProviderID    = apiError(http.StatusBadRequest, "Provider id collides with a built-in account provider and cannot be used for SCIM")
	ErrOrgPluginRequired    = apiError(http.StatusBadRequest, "Restricting a token to an organization requires the organization plugin")
	ErrNotOrgMember         = apiError(http.StatusForbidden, "You are not a member of the organization")
	ErrInsufficientRole     = apiError(http.StatusForbidden, "Insufficient role for this operation")
	ErrNotAllowedToGenerate = apiError(http.StatusForbidden, "You are not allowed to generate a SCIM token")
	ErrSCIMProviderNotFound = apiError(http.StatusNotFound, "SCIM provider not found")
	ErrOrgPluginForProvider = apiError(http.StatusForbidden, "Organization plugin is required to access this SCIM provider")
	ErrMustBeOrgMember      = apiError(http.StatusForbidden, "You must be a member of the organization to access this provider")
	ErrMustBeOwner          = apiError(http.StatusForbidden, "You must be the owner to access this provider")
)
