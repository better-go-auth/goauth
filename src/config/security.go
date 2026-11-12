package config

import (
	"github.com/better-go-auth/goauth/src/common/consts"
)

// SecurityConfig defines operation-level security policies enforced across core and plugin routes.
type SecurityConfig struct {
	// RequireFreshOps lists operation IDs that require a fresh login (within Session.FreshAge).
	// Unauthenticated callers receive 401 UNAUTHORIZED; stale sessions receive 403 SESSION_NOT_FRESH.
	RequireFreshOps []consts.OperationId

	// CheckOriginOnPluginMutations enables Origin/Referer CSRF validation on mutating
	// (non-GET/HEAD/OPTIONS) cookie-authenticated requests across all Huma routes, including
	// plugin routes such as org and admin.
	CheckOriginOnPluginMutations bool
}

// OperationSet builds an O(1) lookup set from a list of OperationIds, ignoring empty entries.
func OperationSet(ops ...[]consts.OperationId) map[string]bool {
	// 1. Preallocate lookup map across all provided lists
	total := 0
	for _, list := range ops {
		total += len(list)
	}
	if total == 0 {
		return nil
	}

	// 2. Populate set with non-empty operation IDs
	set := make(map[string]bool, total)
	for _, list := range ops {
		for _, id := range list {
			if s := id.Str(); s != "" {
				set[s] = true
			}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

