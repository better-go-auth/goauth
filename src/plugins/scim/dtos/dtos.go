// Package dtos holds the request and response bodies of the scim endpoints (@better-auth/scim 1.6.16).
package dtos

// SCIMGenerateTokenInput is the body of POST /scim/generate-token.
type SCIMGenerateTokenInput struct {
	_              struct{} `additionalProperties:"true"`
	ProviderID     string   `json:"providerId" doc:"Unique provider identifier"`
	OrganizationID string   `json:"organizationId,omitempty" doc:"Optional organization id"`
}

// SCIMTokenResponse is {scimToken}.
type SCIMTokenResponse struct {
	SCIMToken string `json:"scimToken" doc:"SCIM token"`
}

// SCIMProviderConnection is a normalized provider connection.
type SCIMProviderConnection struct {
	ID             string  `json:"id"`
	ProviderID     string  `json:"providerId"`
	OrganizationID *string `json:"organizationId"`
}

// SCIMProviderConnections is the body of GET /scim/list-provider-connections.
type SCIMProviderConnections struct {
	Providers []SCIMProviderConnection `json:"providers"`
}

// SCIMProviderIDInput is {providerId}.
type SCIMProviderIDInput struct {
	_          struct{} `additionalProperties:"true"`
	ProviderID string   `json:"providerId"`
}

// SCIMSuccessResponse is {success: true}.
type SCIMSuccessResponse struct {
	Success bool `json:"success"`
}

// SCIMName is the name of a user resource.
type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// SCIMEmail is one email of a user resource.
type SCIMEmail struct {
	Primary *bool  `json:"primary,omitempty"`
	Value   string `json:"value"`
}

// SCIMUserInput is the body of POST /scim/v2/Users and PUT /scim/v2/Users/{userId}.
type SCIMUserInput struct {
	UserName   string      `json:"userName"`
	ExternalID *string     `json:"externalId,omitempty"`
	Name       *SCIMName   `json:"name,omitempty"`
	Emails     []SCIMEmail `json:"emails,omitempty"`
}

// SCIMMeta is the meta of a user resource.
type SCIMMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Location     string `json:"location"`
}

// SCIMUserResource is a SCIM user resource (better-auth's createUserResource).
type SCIMUserResource struct {
	ID          string      `json:"id"`
	ExternalID  string      `json:"externalId,omitempty"`
	Meta        SCIMMeta    `json:"meta"`
	UserName    string      `json:"userName"`
	Name        SCIMName    `json:"name"`
	DisplayName string      `json:"displayName"`
	Active      bool        `json:"active"`
	Emails      []SCIMEmail `json:"emails"`
	Schemas     []string    `json:"schemas"`
}

// SCIMUserList is the body of GET /scim/v2/Users.
type SCIMUserList struct {
	Schemas      []string           `json:"schemas"`
	TotalResults int                `json:"totalResults"`
	StartIndex   int                `json:"startIndex"`
	ItemsPerPage int                `json:"itemsPerPage"`
	Resources    []SCIMUserResource `json:"Resources"`
}

// SCIMPatchOperation is one PatchOp operation.
type SCIMPatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}
