package goauth

import (
	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/config"
	humaadmin "github.com/better-go-auth/goauth/src/plugins/admin/adapters/huma"
	humaorg "github.com/better-go-auth/goauth/src/plugins/org/adapters/huma"
)

// DefaultFreshOperations returns the recommended list of sensitive core, org, and admin
// operations that should require a recent login (within Session.FreshAge).
func DefaultFreshOperations() []consts.OperationId {
	return []consts.OperationId{
		// Identity & account takeover actions
		humaadapter.OpDeleteUser,
		humaadapter.OpChangeEmail,
		humaadapter.OpUnlinkAccount,
		humaadapter.OpChangePassword,

		// Irreversible / high-privilege organization actions
		humaorg.OrDeleteOrg,
		consts.OperationId(humaorg.OrDeleteOrg.Str() + "-Post"),
		humaorg.OrUpdateMemberRole,

		// Irreversible / high-privilege platform admin actions
		humaadmin.AdminSetRole,
		humaadmin.AdminSetUserRole,
		humaadmin.AdminRemoveUser,
		humaadmin.AdminImpersonateUser,
	}
}

// DefaultBearerTokenOperations returns the recommended list of operations that must not be
// authenticated with a short-lived Access JWT (for AccessTokenConfig.RequireBearerTokenOps).
func DefaultBearerTokenOperations() []consts.OperationId {
	ops := DefaultFreshOperations()
	// Include session revocation mutations so a leaked short-lived Access JWT cannot wipe sessions
	ops = append(ops,
		humaadapter.OpRevokeSession,
		humaadapter.OpRevokeSessions,
		humaadapter.OpRevokeOtherSessions,
	)
	return ops
}

// DefaultStrictSecurityConfig returns a SecurityConfig enforcing fresh logins on identity/privilege
// mutations and enabling cookie CSRF origin checks on plugins.
func DefaultStrictSecurityConfig() config.SecurityConfig {
	return config.SecurityConfig{
		RequireFreshOps:              DefaultFreshOperations(),
		CheckOriginOnPluginMutations: true,
	}
}
