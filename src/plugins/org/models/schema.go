package models

import (
	"time"

	coremodels "github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/schema"
)

// Logical model names of the organization plugin's tables (better-auth's organization schema).
const (
	ModelOrganization     = coremodels.ModelOrganization
	ModelMember           = coremodels.ModelMember
	ModelInvitation       = coremodels.ModelInvitation
	ModelTeam             = coremodels.ModelTeam
	ModelTeamMember       = coremodels.ModelTeamMember
	ModelOrganizationRole = coremodels.ModelOrganizationRole
)

// OrgRoleIndex is the unique (organizationId, role) index of organizationRole, named like the index older
// goauth versions created with GORM.
const OrgRoleIndex = "idx_org_role"

// now is the default of goauth's timestamps (GORM's autoCreateTime / autoUpdateTime before).
func now() any { return time.Now() }

// Schema is better-auth's organization plugin schema (plugins/organization/organization.ts, v1.6.16) for the
// organization, member, invitation, team, teamMember and organizationRole tables. team / teamMember (and the
// invitation's teamId) exist only with teams, organizationRole only with dynamic access control, like in
// better-auth. The session's activeOrganizationId / activeTeamId fields are declared with the core session.
//
// goauth's own fields are kept on top, all nullable or with a default so a TypeScript better-auth server can
// insert rows into the same tables: updatedAt on every table, the organization's status, createdBy and
// orgType, the invitation's acceptedById / acceptedAt, the organization role's ops and its unique
// (organizationId, role) index. goauth also gives createdAt a default (better-auth always writes it).
//
// The logical names equal the columns the GORM structs of older goauth versions created (snake_case, or
// camelCase with ColumnCase camel), so existing databases keep working without a migration.
func Schema(teams, dynamicAccessControl bool) schema.PluginSchema {
	ref := func(model string) *schema.Reference { return &schema.Reference{Model: model, Field: "id"} }
	noInput := schema.Bool(false)
	out := schema.PluginSchema{
		// Step 1: organization
		ModelOrganization: {Fields: map[string]schema.Field{
			"name":      {Type: schema.String, Required: true, Sortable: true},
			"slug":      {Type: schema.String, Required: true, Unique: true, Sortable: true, Index: true},
			"logo":      {Type: schema.String},
			"createdAt": {Type: schema.Date, Required: true, Default: now},
			"metadata":  {Type: schema.String},
			// goauth fields
			"updatedAt": {Type: schema.Date, Default: now, OnUpdate: now},
			"status":    {Type: schema.String, Required: true, Default: string(OrgStatusActive), Input: noInput},
			"createdBy": {Type: schema.String, Index: true, Input: noInput},
			"orgType":   {Type: schema.String},
		}},
		// Step 2: member
		ModelMember: {Fields: map[string]schema.Field{
			"organizationId": {Type: schema.String, Required: true, Index: true, References: ref(ModelOrganization)},
			"userId":         {Type: schema.String, Required: true, Index: true, References: ref(schema.ModelUser)},
			"role":           {Type: schema.String, Required: true, Sortable: true, Default: string(OrgRoleMember)},
			"createdAt":      {Type: schema.Date, Required: true, Default: now},
			// goauth fields
			"updatedAt": {Type: schema.Date, Default: now, OnUpdate: now},
		}},
		// Step 3: invitation
		ModelInvitation: {Fields: map[string]schema.Field{
			"organizationId": {Type: schema.String, Required: true, Index: true, References: ref(ModelOrganization)},
			"email":          {Type: schema.String, Required: true, Sortable: true, Index: true},
			"role":           {Type: schema.String, Sortable: true},
			"status":         {Type: schema.String, Required: true, Sortable: true, Default: string(InvitationPending)},
			"expiresAt":      {Type: schema.Date, Required: true},
			"createdAt":      {Type: schema.Date, Required: true, Default: now},
			"inviterId":      {Type: schema.String, Required: true, References: ref(schema.ModelUser)},
			// goauth fields
			"updatedAt":    {Type: schema.Date, Default: now, OnUpdate: now},
			"acceptedById": {Type: schema.String, Input: noInput},
			"acceptedAt":   {Type: schema.Date, Input: noInput},
		}},
	}
	// Step 4: teams
	if teams {
		out[ModelInvitation].Fields["teamId"] = schema.Field{Type: schema.String, Sortable: true}
		out[ModelTeam] = schema.Model{Fields: map[string]schema.Field{
			"name":           {Type: schema.String, Required: true},
			"organizationId": {Type: schema.String, Required: true, Index: true, References: ref(ModelOrganization)},
			"createdAt":      {Type: schema.Date, Required: true, Default: now},
			"updatedAt":      {Type: schema.Date, Default: now, OnUpdate: now},
		}}
		out[ModelTeamMember] = schema.Model{Fields: map[string]schema.Field{
			"teamId":    {Type: schema.String, Required: true, Index: true, References: ref(ModelTeam)},
			"userId":    {Type: schema.String, Required: true, Index: true, References: ref(schema.ModelUser)},
			"createdAt": {Type: schema.Date, Default: now},
			// goauth fields
			"updatedAt": {Type: schema.Date, Default: now, OnUpdate: now},
		}}
	}
	// Step 5: dynamic access control
	if dynamicAccessControl {
		out[ModelOrganizationRole] = schema.Model{
			Fields: map[string]schema.Field{
				"organizationId": {Type: schema.String, Required: true, Index: true, References: ref(ModelOrganization)},
				"role":           {Type: schema.String, Required: true, Index: true},
				"permission":     {Type: schema.String, Required: true},
				"createdAt":      {Type: schema.Date, Required: true, Default: now},
				"updatedAt":      {Type: schema.Date, Default: now, OnUpdate: now},
				// goauth fields
				"ops": {Type: schema.String},
			},
			Indexes: []schema.Index{{Name: OrgRoleIndex, Fields: []string{"organizationId", "role"}, Unique: true}},
		}
	}
	return out
}
