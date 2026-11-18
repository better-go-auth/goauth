package schema

import (
	"time"
)

// Plugin IDs that own columns goauth's core models still carry as typed Go fields. A later step drops these
// fields from the registry when their plugin is not installed (Options.InstalledPlugins).
const (
	PluginAdmin       = "admin"
	PluginPhoneNumber = "phone-number"
	PluginTwoFactor   = "two-factor"
	PluginUsername    = "username"
	PluginAnonymous   = "anonymous"
	PluginOrg         = "org"
)

// now is the default / onUpdate value of better-auth's createdAt and updatedAt fields.
func now() any { return time.Now() }

// namedField keeps the definition order of the core models (Go maps are unordered).
type namedField struct {
	name  string
	field Field
}

// coreModel is one core table definition in better-auth's order.
type coreModel struct {
	name    string
	fields  []namedField
	indexes []Index
}

// owned returns fields with their Owner set to owner.
func owned(owner string, fields ...namedField) []namedField {
	for i := range fields {
		fields[i].field.Owner = owner
	}
	return fields
}

// idField is the primary key every model has (better-auth's adapters add it implicitly).
func idField() namedField {
	return namedField{"id", Field{Type: ID, Required: true, Input: Bool(false)}}
}

// coreModels returns better-auth's getAuthTables (v1.6.16) for user, session, account and verification,
// followed by goauth's built-in columns and the plugin columns goauth's models still hard-code.
func coreModels() []coreModel {
	f := Bool(false)
	user := coreModel{name: ModelUser}
	// Step 1: better-auth core user fields
	user.fields = append(user.fields, owned(OwnerCore,
		idField(),
		namedField{"name", Field{Type: String, Required: true, Sortable: true}},
		namedField{"email", Field{Type: String, Unique: true, Required: true, Sortable: true}},
		namedField{"emailVerified", Field{Type: Boolean, Default: false, Required: true, Input: f}},
		namedField{"image", Field{Type: String}},
		namedField{"createdAt", Field{Type: Date, Default: now, Required: true}},
		namedField{"updatedAt", Field{Type: Date, Default: now, OnUpdate: now, Required: true}},
	)...)
	// Step 2: plugin fields still stored on models.User (better-auth's plugin schemas)
	user.fields = append(user.fields, owned(PluginAdmin,
		namedField{"role", Field{Type: String, Input: f}},
		namedField{"banned", Field{Type: Boolean, Default: false, Input: f}},
		namedField{"banReason", Field{Type: String, Input: f}},
		namedField{"banExpires", Field{Type: Date, Input: f}},
	)...)
	user.fields = append(user.fields, owned(PluginPhoneNumber,
		namedField{"phoneNumber", Field{Type: String, Unique: true, Sortable: true, Returned: Bool(true)}},
		namedField{"phoneNumberVerified", Field{Type: Boolean, Returned: Bool(true), Input: f}},
	)...)
	user.fields = append(user.fields, owned(PluginTwoFactor,
		namedField{"twoFactorEnabled", Field{Type: Boolean, Default: false, Input: f}},
	)...)
	user.fields = append(user.fields, owned(PluginUsername,
		namedField{"username", Field{Type: String, Sortable: true, Unique: true, Returned: Bool(true)}},
		namedField{"displayUsername", Field{Type: String}},
	)...)
	user.fields = append(user.fields, owned(PluginAnonymous,
		namedField{"isAnonymous", Field{Type: Boolean, Input: f, Default: false}},
	)...)
	// Step 3: goauth's own user columns (profile fields clients may set, bookkeeping fields they can't)
	user.fields = append(user.fields, owned(OwnerGoAuth,
		namedField{"firstName", Field{Type: String}},
		namedField{"lastName", Field{Type: String}},
		namedField{"displayName", Field{Type: String}},
		namedField{"bio", Field{Type: String}},
		namedField{"dateOfBirth", Field{Type: Date}},
		namedField{"gender", Field{Type: String}},
		namedField{"locale", Field{Type: String, Default: "en"}},
		namedField{"timezone", Field{Type: String}},
		namedField{"lastLoginIP", Field{Type: String, Input: f, Returned: f}},
		namedField{"lastLoginAt", Field{Type: Date, Input: f, Returned: f}},
		namedField{"lastSeen", Field{Type: Date, Input: f, Returned: f}},
		// deletedAt marks soft-deleted tombstones (User.GoAuth.SoftDelete)
		namedField{"deletedAt", Field{Type: Date, Input: f, Returned: f, Index: true}},
	)...)

	session := coreModel{name: ModelSession}
	// Step 4: better-auth core session fields
	session.fields = append(session.fields, owned(OwnerCore,
		idField(),
		namedField{"expiresAt", Field{Type: Date, Required: true}},
		namedField{"token", Field{Type: String, Required: true, Unique: true}},
		namedField{"createdAt", Field{Type: Date, Required: true, Default: now}},
		namedField{"updatedAt", Field{Type: Date, Required: true, OnUpdate: now}},
		namedField{"ipAddress", Field{Type: String}},
		namedField{"userAgent", Field{Type: String}},
		namedField{"userId", Field{Type: String, References: &Reference{Model: ModelUser, Field: "id", OnDelete: Cascade}, Required: true, Index: true}},
	)...)
	// Step 5: plugin session fields (admin impersonation, organization)
	session.fields = append(session.fields, owned(PluginAdmin,
		namedField{"impersonatedBy", Field{Type: String, Input: f}},
	)...)
	session.fields = append(session.fields, owned(PluginOrg,
		namedField{"activeOrganizationId", Field{Type: String, Input: f}},
		namedField{"activeTeamId", Field{Type: String, Input: f}},
		// goauth-only organization fields (not in better-auth's organization schema)
		namedField{"activeOrganizationType", Field{Type: String, Input: f}},
		namedField{"activeOrganizationRole", Field{Type: String, Input: f}},
	)...)
	// Step 6: goauth's device fields (settable through /update-session) and bookkeeping
	session.fields = append(session.fields, owned(OwnerGoAuth,
		namedField{"deviceToken", Field{Type: String}},
		namedField{"deviceId", Field{Type: String}},
		namedField{"deviceName", Field{Type: String}},
		namedField{"deviceType", Field{Type: String}},
		namedField{"lastUsedAt", Field{Type: Date, Input: f, Returned: f}},
	)...)

	account := coreModel{name: ModelAccount}
	// Step 7: better-auth core account fields
	account.fields = owned(OwnerCore,
		idField(),
		namedField{"accountId", Field{Type: String, Required: true}},
		namedField{"providerId", Field{Type: String, Required: true}},
		namedField{"userId", Field{Type: String, References: &Reference{Model: ModelUser, Field: "id", OnDelete: Cascade}, Required: true, Index: true}},
		namedField{"accessToken", Field{Type: String, Returned: f}},
		namedField{"refreshToken", Field{Type: String, Returned: f}},
		namedField{"idToken", Field{Type: String, Returned: f}},
		namedField{"accessTokenExpiresAt", Field{Type: Date, Returned: f}},
		namedField{"refreshTokenExpiresAt", Field{Type: Date, Returned: f}},
		namedField{"scope", Field{Type: String}},
		namedField{"password", Field{Type: String, Returned: f}},
		namedField{"createdAt", Field{Type: Date, Required: true, Default: now}},
		namedField{"updatedAt", Field{Type: Date, Required: true, OnUpdate: now}},
	)
	// Step 8: goauth keeps (providerId, accountId) unique (better-auth has no such constraint)
	account.indexes = []Index{{Name: "idx_provider_account", Fields: []string{"providerId", "accountId"}, Unique: true, Owner: OwnerGoAuth}}

	verification := coreModel{name: ModelVerification}
	// Step 9: better-auth core verification fields
	verification.fields = append(verification.fields, owned(OwnerCore,
		idField(),
		namedField{"identifier", Field{Type: String, Required: true, Index: true}},
		namedField{"value", Field{Type: String, Required: true}},
		namedField{"expiresAt", Field{Type: Date, Required: true}},
		namedField{"createdAt", Field{Type: Date, Required: true, Default: now}},
		namedField{"updatedAt", Field{Type: Date, Required: true, Default: now, OnUpdate: now}},
	)...)
	// Step 10: goauth's verification columns
	verification.fields = append(verification.fields, owned(OwnerGoAuth,
		namedField{"userId", Field{Type: String}},
		namedField{"callbackUrl", Field{Type: String}},
	)...)

	return []coreModel{user, session, account, verification}
}

// rateLimitModel is better-auth's rateLimit table (getAuthTables with rateLimit.storage = "database"):
// one row per rate-limit key, lastRequest in Unix milliseconds.
func rateLimitModel() Model {
	return Model{Fields: map[string]Field{
		"id":          {Type: ID, Required: true, Input: Bool(false), Owner: OwnerCore},
		"key":         {Type: String, Required: true, Unique: true, Owner: OwnerCore},
		"count":       {Type: Integer, Required: true, Owner: OwnerCore},
		"lastRequest": {Type: Integer, Required: true, Default: func() any { return time.Now().UnixMilli() }, Owner: OwnerCore},
	}}
}

// Core returns the core model definitions (user, session, account, verification) with goauth's built-in
// and plugin-owned columns. Every call returns fresh maps.
func Core() map[string]Model {
	out := map[string]Model{}
	for _, cm := range coreModels() {
		m := Model{Fields: map[string]Field{}, Indexes: append([]Index(nil), cm.indexes...)}
		for _, nf := range cm.fields {
			m.Fields[nf.name] = nf.field
		}
		out[cm.name] = m
	}
	return out
}

// coreOrder returns the definition order of each core model's fields.
func coreOrder() map[string][]string {
	out := map[string][]string{}
	for _, cm := range coreModels() {
		for _, nf := range cm.fields {
			out[cm.name] = append(out[cm.name], nf.name)
		}
	}
	out[ModelRateLimit] = []string{"id", "key", "count", "lastRequest"}
	return out
}
