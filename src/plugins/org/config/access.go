package config

import (
	"sort"

	"github.com/better-go-auth/goauth/src/providers/access"
)

// DefaultStatements mirrors better-auth's organization `defaultStatements`
// (plugins/organization/access/statement.ts).
var DefaultStatements = access.Statements{
	"organization": {"update", "delete"},
	"member":       {"create", "update", "delete"},
	"invitation":   {"create", "cancel"},
	"team":         {"create", "update", "delete"},
	"ac":           {"create", "read", "update", "delete"},
}

// DefaultAC mirrors better-auth's organization `defaultAc`.
var DefaultAC = access.NewAccessControl(DefaultStatements)

// OwnerAC mirrors better-auth's `ownerAc`.
var OwnerAC = DefaultAC.NewRole(access.Statements{
	"organization": {"update", "delete"},
	"member":       {"create", "update", "delete"},
	"invitation":   {"create", "cancel"},
	"team":         {"create", "update", "delete"},
	"ac":           {"create", "read", "update", "delete"},
})

// AdminAC mirrors better-auth's `adminAc` (everything but organization:delete).
var AdminAC = DefaultAC.NewRole(access.Statements{
	"organization": {"update"},
	"invitation":   {"create", "cancel"},
	"member":       {"create", "update", "delete"},
	"team":         {"create", "update", "delete"},
	"ac":           {"create", "read", "update", "delete"},
})

// MemberAC mirrors better-auth's `memberAc` (ac:read only).
var MemberAC = DefaultAC.NewRole(access.Statements{
	"organization": {},
	"member":       {},
	"invitation":   {},
	"team":         {},
	"ac":           {"read"},
})

// DefaultRoles returns better-auth's organization `defaultRoles` ({owner, admin, member}).
func DefaultRoles() access.Roles {
	return access.Roles{"owner": OwnerAC, "admin": AdminAC, "member": MemberAC}
}

// BetterAuthMode reports whether organization permissions follow better-auth exactly. That is the
// default; goauth's legacy rules (owner bypass, built-in admin/member rules, Config.Roles with "*"
// wildcards — see OrgService.HasPermissions) apply only when GoAuth.LegacyPermissions is set or the
// legacy Roles map is configured, and never when AccessControl / AccessRoles is set.
func (c OrgConfig) BetterAuthMode() bool {
	// Step 1: better-auth options always win
	if c.AccessControl != nil || c.AccessRoles != nil || c.BetterAuthPermissions {
		return true
	}
	// Step 2: legacy rules only on explicit goauth configuration
	return !c.GoAuth.LegacyPermissions && len(c.Roles) == 0
}

// EffectiveAC returns the configured AccessControl, or better-auth's default organization one.
func (c OrgConfig) EffectiveAC() *access.AccessControl {
	if c.AccessControl != nil {
		return c.AccessControl
	}
	return DefaultAC
}

// EffectiveRoles returns a fresh copy of the predefined access roles used in better-auth mode:
// AccessRoles when set (replacing the defaults, like better-auth `options.roles || defaultRoles`),
// else the default owner/admin/member roles.
func (c OrgConfig) EffectiveRoles() access.Roles {
	src := c.AccessRoles
	if src == nil {
		src = DefaultRoles()
	}
	out := make(access.Roles, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// PredefinedRoleNames lists the role names that dynamic roles may not reuse or delete
// (better-auth: keys of `roles`, or owner/admin/member). In legacy mode the built-in
// owner/admin/member names are always reserved, plus the Config.Roles keys.
func (c OrgConfig) PredefinedRoleNames() []string {
	set := map[string]bool{}
	switch {
	case c.BetterAuthMode() && c.AccessRoles != nil:
		for k := range c.AccessRoles {
			set[k] = true
		}
	case c.BetterAuthMode():
		set["owner"], set["admin"], set["member"] = true, true, true
	default:
		set["owner"], set["admin"], set["member"] = true, true, true
		for k := range c.Roles {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsPredefinedRole reports whether name is one of PredefinedRoleNames.
func (c OrgConfig) IsPredefinedRole(name string) bool {
	for _, r := range c.PredefinedRoleNames() {
		if r == name {
			return true
		}
	}
	return false
}
