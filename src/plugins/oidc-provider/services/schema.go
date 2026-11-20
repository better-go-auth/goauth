package services

import (
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/schema"
)

// Schema returns better-auth's oidc-provider tables (oauthApplication, oauthAccessToken, oauthConsent) with
// the plugin's `schema` renames applied. The mcp plugin declares the same tables.
func Schema(renames map[string]oidcconfig.ModelSchemaOptions) schema.PluginSchema {
	// Step 1: the references every table shares
	userRef := &schema.Reference{Model: schema.ModelUser, Field: "id", OnDelete: schema.Cascade}
	clientRef := &schema.Reference{Model: oidcconfig.ModelOAuthApplication, Field: "clientId", OnDelete: schema.Cascade}
	// Step 2: the three models, field for field like better-auth's schema.ts
	out := schema.PluginSchema{
		oidcconfig.ModelOAuthApplication: {
			ModelName: oidcconfig.ModelOAuthApplication,
			Fields: map[string]schema.Field{
				"name":         {Type: schema.String, Required: true},
				"icon":         {Type: schema.String},
				"metadata":     {Type: schema.String},
				"clientId":     {Type: schema.String, Required: true, Unique: true},
				"clientSecret": {Type: schema.String},
				"redirectUrls": {Type: schema.String, Required: true},
				"type":         {Type: schema.String, Required: true},
				"disabled":     {Type: schema.Boolean, Default: false},
				"userId":       {Type: schema.String, References: userRef, Index: true},
				"createdAt":    {Type: schema.Date, Required: true},
				"updatedAt":    {Type: schema.Date, Required: true},
			},
		},
		oidcconfig.ModelOAuthAccessToken: {
			ModelName: oidcconfig.ModelOAuthAccessToken,
			Fields: map[string]schema.Field{
				"accessToken":           {Type: schema.String, Required: true, Unique: true},
				"refreshToken":          {Type: schema.String, Required: true, Unique: true},
				"accessTokenExpiresAt":  {Type: schema.Date, Required: true},
				"refreshTokenExpiresAt": {Type: schema.Date, Required: true},
				"clientId":              {Type: schema.String, Required: true, References: clientRef, Index: true},
				"userId":                {Type: schema.String, References: userRef, Index: true},
				"scopes":                {Type: schema.String, Required: true},
				"createdAt":             {Type: schema.Date, Required: true},
				"updatedAt":             {Type: schema.Date, Required: true},
			},
		},
		oidcconfig.ModelOAuthConsent: {
			ModelName: oidcconfig.ModelOAuthConsent,
			Fields: map[string]schema.Field{
				"clientId":     {Type: schema.String, Required: true, References: clientRef, Index: true},
				"userId":       {Type: schema.String, Required: true, References: userRef, Index: true},
				"scopes":       {Type: schema.String, Required: true},
				"createdAt":    {Type: schema.Date, Required: true},
				"updatedAt":    {Type: schema.Date, Required: true},
				"consentGiven": {Type: schema.Boolean, Required: true},
			},
		},
	}
	// Step 3: better-auth's mergeSchema(schema, options.schema): table and column renames
	for model, o := range renames {
		m, ok := out[model]
		if !ok {
			continue
		}
		if o.ModelName != "" {
			m.ModelName = o.ModelName
		}
		for field, column := range o.Fields {
			if f, ok := m.Fields[field]; ok && column != "" {
				f.FieldName = column
				m.Fields[field] = f
			}
		}
		out[model] = m
	}
	return out
}
