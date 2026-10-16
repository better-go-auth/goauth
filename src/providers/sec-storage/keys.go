package sec_storage

// Shared key prefixes for secondary storage.
const (
	// SidPrefix is the key prefix for the sid -> token index owned by the access-token plugin.
	SidPrefix = "sid:"

	// ActiveSessionsPrefix is the prefix for the per-user active session list.
	ActiveSessionsPrefix = "active-sessions-"

	// RevokedSessionPrefix is the prefix for explicitly revoked sessions (replaces legacy "blacklist:").
	RevokedSessionPrefix = "revoked:session:"

	// RevokedTokenPrefix is the prefix for explicitly blacklisted tokens.
	RevokedTokenPrefix = "blacklist:token:"

	// LegacyBlacklistPrefix is the old prefix kept for compat reads until existing entries expire.
	LegacyBlacklistPrefix = "blacklist:"
)
