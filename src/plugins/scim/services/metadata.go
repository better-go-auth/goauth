package services

import (
	"net/url"
	"strings"
)

// Schema URNs.
const (
	UserSchemaID       = "urn:ietf:params:scim:schemas:core:2.0:User"
	ListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	PatchOpSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// SCIMSchemaAttribute is one attribute of a SCIM schema (RFC 7643 §7).
type SCIMSchemaAttribute struct {
	Name          string                `json:"name"`
	Type          string                `json:"type"`
	MultiValued   bool                  `json:"multiValued"`
	Description   string                `json:"description"`
	Required      bool                  `json:"required"`
	CaseExact     *bool                 `json:"caseExact,omitempty"`
	SubAttributes []SCIMSchemaAttribute `json:"subAttributes,omitempty"`
	Mutability    string                `json:"mutability,omitempty"`
	Returned      string                `json:"returned,omitempty"`
	Uniqueness    string                `json:"uniqueness,omitempty"`
}

// SCIMMetaRef is {resourceType, location}.
type SCIMMetaRef struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location"`
}

// SCIMSchemaResource is a SCIM schema (better-auth's SCIMUserResourceSchema).
type SCIMSchemaResource struct {
	ID          string                `json:"id"`
	Schemas     []string              `json:"schemas"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Attributes  []SCIMSchemaAttribute `json:"attributes"`
	Meta        SCIMMetaRef           `json:"meta"`
}

// SCIMResourceType is a SCIM resource type (better-auth's SCIMUserResourceType).
type SCIMResourceType struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Endpoint    string      `json:"endpoint"`
	Description string      `json:"description"`
	Schema      string      `json:"schema"`
	Meta        SCIMMetaRef `json:"meta"`
}

func boolPtr(b bool) *bool { return &b }

// userSchema is better-auth's SCIMUserResourceSchema.
var userSchema = SCIMSchemaResource{
	ID:          UserSchemaID,
	Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
	Name:        "User",
	Description: "User Account",
	Attributes: []SCIMSchemaAttribute{
		{Name: "id", Type: "string", Description: "Unique opaque identifier for the User", CaseExact: boolPtr(true), Mutability: "readOnly", Returned: "default", Uniqueness: "server"},
		{Name: "userName", Type: "string", Description: "Unique identifier for the User, typically used by the user to directly authenticate to the service provider", Required: true, CaseExact: boolPtr(false), Mutability: "readWrite", Returned: "default", Uniqueness: "server"},
		{Name: "displayName", Type: "string", Description: "The name of the User, suitable for display to end-users.  The name SHOULD be the full name of the User being described, if known.", CaseExact: boolPtr(true), Mutability: "readOnly", Returned: "default", Uniqueness: "none"},
		{Name: "active", Type: "boolean", Description: "A Boolean value indicating the User's administrative status.", Mutability: "readOnly", Returned: "default"},
		{Name: "name", Type: "complex", Description: "The components of the user's real name.", SubAttributes: []SCIMSchemaAttribute{
			{Name: "formatted", Type: "string", Description: "The full name, including all middlenames, titles, and suffixes as appropriate, formatted for display(e.g., 'Ms. Barbara J Jensen, III').", CaseExact: boolPtr(false), Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
			{Name: "familyName", Type: "string", Description: "The family name of the User, or last name in most Western languages (e.g., 'Jensen' given the fullname 'Ms. Barbara J Jensen, III').", CaseExact: boolPtr(false), Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
			{Name: "givenName", Type: "string", Description: "The given name of the User, or first name in most Western languages (e.g., 'Barbara' given the full name 'Ms. Barbara J Jensen, III').", CaseExact: boolPtr(false), Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
		}},
		{Name: "emails", Type: "complex", MultiValued: true, Description: "Email addresses for the user.  The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.", SubAttributes: []SCIMSchemaAttribute{
			{Name: "value", Type: "string", Description: "Email addresses for the user.  The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.", CaseExact: boolPtr(false), Mutability: "readWrite", Returned: "default", Uniqueness: "server"},
			{Name: "primary", Type: "boolean", Description: "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred mailing address or primary email address.  The primary attribute value 'true' MUST appear no more than once.", Mutability: "readWrite", Returned: "default"},
		}, Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
	},
	Meta: SCIMMetaRef{ResourceType: "Schema", Location: "/scim/v2/Schemas/" + UserSchemaID},
}

// userResourceType is better-auth's SCIMUserResourceType.
var userResourceType = SCIMResourceType{
	Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
	ID:          "User",
	Name:        "User",
	Endpoint:    "/Users",
	Description: "User Account",
	Schema:      UserSchemaID,
	Meta:        SCIMMetaRef{ResourceType: "ResourceType", Location: "/scim/v2/ResourceTypes/User"},
}

// resourceURL is better-auth's getResourceURL: path resolved under baseURL (with a trailing slash).
func resourceURL(path, baseURL string) string {
	base := baseURL
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	b, err := url.Parse(base)
	if err != nil {
		return base + strings.TrimLeft(path, "/")
	}
	u, err := b.Parse(strings.TrimLeft(path, "/"))
	if err != nil {
		return base + strings.TrimLeft(path, "/")
	}
	return u.String()
}

// SCIMServiceProviderConfig is the body of GET /scim/v2/ServiceProviderConfig.
type SCIMServiceProviderConfig struct {
	Patch                 SCIMSupported    `json:"patch"`
	Bulk                  SCIMSupported    `json:"bulk"`
	Filter                SCIMSupported    `json:"filter"`
	ChangePassword        SCIMSupported    `json:"changePassword"`
	Sort                  SCIMSupported    `json:"sort"`
	Etag                  SCIMSupported    `json:"etag"`
	AuthenticationSchemes []SCIMAuthScheme `json:"authenticationSchemes"`
	Schemas               []string         `json:"schemas"`
	Meta                  struct {
		ResourceType string `json:"resourceType"`
	} `json:"meta"`
}

// SCIMSupported is {supported}.
type SCIMSupported struct {
	SCIMSupported bool `json:"supported"`
}

// SCIMAuthScheme is one authentication scheme of the service provider config.
type SCIMAuthScheme struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SpecURI     string `json:"specUri"`
	Type        string `json:"type"`
	Primary     bool   `json:"primary"`
}

// ServiceProviderConfiguration returns better-auth's static service provider configuration.
func ServiceProviderConfiguration() SCIMServiceProviderConfig {
	c := SCIMServiceProviderConfig{
		Patch: SCIMSupported{true}, Bulk: SCIMSupported{false}, Filter: SCIMSupported{true},
		ChangePassword: SCIMSupported{false}, Sort: SCIMSupported{false}, Etag: SCIMSupported{false},
		AuthenticationSchemes: []SCIMAuthScheme{{
			Name:        "OAuth Bearer Token",
			Description: "Authentication scheme using the Authorization header with a bearer token tied to an organization.",
			SpecURI:     "http://www.rfc-editor.org/info/rfc6750",
			Type:        "oauthbearertoken",
			Primary:     true,
		}},
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
	}
	c.Meta.ResourceType = "ServiceProviderConfig"
	return c
}

// SCIMListResponse is a SCIM ListResponse.
type SCIMListResponse[T any] struct {
	TotalResults int      `json:"totalResults"`
	ItemsPerPage int      `json:"itemsPerPage"`
	StartIndex   int      `json:"startIndex"`
	Schemas      []string `json:"schemas"`
	Resources    []T      `json:"Resources"`
}

// Schemas returns GET /scim/v2/Schemas.
func Schemas(baseURL string) SCIMListResponse[SCIMSchemaResource] {
	s := userSchema
	s.Meta.Location = resourceURL(s.Meta.Location, baseURL)
	return SCIMListResponse[SCIMSchemaResource]{TotalResults: 1, ItemsPerPage: 1, StartIndex: 1, Schemas: []string{ListResponseSchema}, Resources: []SCIMSchemaResource{s}}
}

// Schema returns GET /scim/v2/Schemas/{schemaId}.
func Schema(baseURL, id string) (*SCIMSchemaResource, error) {
	if id != userSchema.ID {
		return nil, ErrSchemaNotFound
	}
	s := userSchema
	s.Meta.Location = resourceURL(s.Meta.Location, baseURL)
	return &s, nil
}

// ResourceTypes returns GET /scim/v2/ResourceTypes.
func ResourceTypes(baseURL string) SCIMListResponse[SCIMResourceType] {
	r := userResourceType
	r.Meta.Location = resourceURL(r.Meta.Location, baseURL)
	return SCIMListResponse[SCIMResourceType]{TotalResults: 1, ItemsPerPage: 1, StartIndex: 1, Schemas: []string{ListResponseSchema}, Resources: []SCIMResourceType{r}}
}

// ResourceTypeByID returns GET /scim/v2/ResourceTypes/{resourceTypeId}.
func ResourceTypeByID(baseURL, id string) (*SCIMResourceType, error) {
	if id != userResourceType.ID {
		return nil, ErrResourceNotFound
	}
	r := userResourceType
	r.Meta.Location = resourceURL(r.Meta.Location, baseURL)
	return &r, nil
}
