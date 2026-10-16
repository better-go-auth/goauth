package sec_storage

// Key prefixes for secondary storage managed by the core.
const (
	// ActiveSessionsPrefix is the prefix for the per-user active session list.
	ActiveSessionsPrefix = "active-sessions-"

	// RevokedSessionPrefix is the prefix for explicitly revoked sessions.
	RevokedSessionPrefix = "revoked:session:"
)
