package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SecretsEnvVar holds versioned secrets as "<version>:<secret>,<version>:<secret>" (better-auth's
// BETTER_AUTH_SECRETS). It is read when AuthConfig.Secrets is empty.
const SecretsEnvVar = "BETTER_AUTH_SECRETS"

// SecretVersion is one entry of better-auth's `secrets` option (secret rotation).
//
// The first entry of AuthConfig.Secrets is the current secret: it signs cookies and tokens and encrypts new
// data, written as a "$ba$<version>$<hex>" envelope. The other entries only decrypt data (and, as a goauth
// extension, verify cookie signatures) written with them, so rotating a secret does not log users out or make
// stored two-factor secrets, OAuth tokens or JWKS private keys unreadable.
//
//	Secrets: []config.SecretVersion{
//		{Version: 2, Value: os.Getenv("AUTH_SECRET_V2")}, // current
//		{Version: 1, Value: os.Getenv("AUTH_SECRET_V1")}, // still decrypts old data
//	}
type SecretVersion struct {
	// Version is a non-negative integer, unique within Secrets. It is written into every envelope.
	Version int
	// Value is the secret itself (at least 32 random characters for the current one).
	Value string
}

// secretState is the secret rotation state resolved by SetDefaults.
type secretState struct {
	// applied is set once Secrets were resolved, so a second SetDefaults call keeps the legacy secret.
	applied bool
	// legacy is better-auth's legacySecret: options.secret || $BETTER_AUTH_SECRET || $AUTH_SECRET, used to
	// decrypt bare-hex payloads written before rotation was enabled (never the public dev default).
	legacy string
	// envErr is a parse error of $BETTER_AUTH_SECRETS, reported by Validate.
	envErr error
}

// LegacySecret returns the secret that decrypts bare-hex payloads written before Secrets was configured
// (better-auth's secretConfig.legacySecret): Secret, $BETTER_AUTH_SECRET or $AUTH_SECRET. It is "" without
// Secrets, and never the public development default.
func (opts AuthConfig) LegacySecret() string {
	if len(opts.Secrets) == 0 {
		return ""
	}
	if opts.secrets.applied {
		return opts.secrets.legacy
	}
	// SetDefaults was not called: Secret still holds what the app configured
	if opts.Secret != opts.Secrets[0].Value && opts.Secret != DefaultDevSecret {
		return opts.Secret
	}
	return ""
}

// CurrentSecret returns the secret that signs and encrypts new data: the first entry of Secrets, else Secret.
func (opts AuthConfig) CurrentSecret() string {
	if len(opts.Secrets) > 0 {
		return opts.Secrets[0].Value
	}
	return opts.Secret
}

// resolveSecrets is SetDefaults' secret step, ported from better-auth's createAuthContext:
// secrets = options.secrets ?? parse($BETTER_AUTH_SECRETS); legacy = options.secret || $BETTER_AUTH_SECRET ||
// $AUTH_SECRET. With secrets, Secret becomes the current secret (better-auth's ctx.secret).
func (opts *AuthConfig) resolveSecrets() {
	// Step 1: already resolved (SetDefaults called twice): keep the recorded legacy secret
	if opts.secrets.applied {
		return
	}
	// Step 2: versioned secrets from the environment when none are configured
	if len(opts.Secrets) == 0 {
		parsed, err := ParseSecretsEnv(os.Getenv(SecretsEnvVar))
		if err != nil {
			opts.secrets.envErr = err
		}
		opts.Secrets = parsed
	}
	// Step 3: the legacy secret, as better-auth reads it
	legacy := opts.Secret
	if legacy == "" {
		legacy = os.Getenv(SecretEnvVar)
	}
	if legacy == "" {
		legacy = os.Getenv(AuthSecretEnvVar)
	}
	// Step 4: without versioned secrets nothing else changes (Secret keeps better-auth's single-secret mode)
	if len(opts.Secrets) == 0 {
		return
	}
	// Step 5: the current secret signs everything, the legacy one only decrypts bare-hex payloads
	if legacy == DefaultDevSecret {
		legacy = ""
	}
	opts.secrets = secretState{applied: true, legacy: legacy}
	opts.Secret = opts.Secrets[0].Value
}

// ParseSecretsEnv parses better-auth's BETTER_AUTH_SECRETS format "<version>:<secret>,<version>:<secret>".
// An empty value returns (nil, nil).
func ParseSecretsEnv(value string) ([]SecretVersion, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var out []SecretVersion
	for _, entry := range strings.Split(value, ",") {
		// Step 1: every entry is "<version>:<secret>"
		entry = strings.TrimSpace(entry)
		v, secret, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("invalid %s entry %q: expected format \"<version>:<secret>\"", SecretsEnvVar, entry)
		}
		// Step 2: the version is a non-negative integer
		version, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || version < 0 {
			return nil, fmt.Errorf("invalid version in %s: %q; version must be a non-negative integer", SecretsEnvVar, v)
		}
		// Step 3: the secret is not empty
		secret = strings.TrimSpace(secret)
		if secret == "" {
			return nil, fmt.Errorf("empty secret value for version %d in %s", version, SecretsEnvVar)
		}
		out = append(out, SecretVersion{Version: version, Value: secret})
	}
	return out, nil
}

// validateSecrets is better-auth's validateSecretsArray: at least one entry, non-negative unique versions,
// non-empty values. It returns warnings (short current secret) separately.
func validateSecrets(secrets []SecretVersion) (warnings []string, err error) {
	if len(secrets) == 0 {
		return nil, errors.New("goauth: Secrets must contain at least one entry")
	}
	seen := make(map[int]bool, len(secrets))
	for _, s := range secrets {
		if s.Version < 0 {
			return nil, fmt.Errorf("goauth: invalid version %d in Secrets; version must be a non-negative integer", s.Version)
		}
		if s.Value == "" {
			return nil, fmt.Errorf("goauth: empty secret value for version %d in Secrets", s.Version)
		}
		if seen[s.Version] {
			return nil, fmt.Errorf("goauth: duplicate version %d in Secrets; each version must be unique", s.Version)
		}
		seen[s.Version] = true
	}
	if len(secrets[0].Value) < MinSecretLength {
		warnings = append(warnings, fmt.Sprintf("goauth: the current secret (version %d) should be at least %d characters long", secrets[0].Version, MinSecretLength))
	}
	return warnings, nil
}
