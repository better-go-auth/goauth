package authcrypto

import (
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/better-go-auth/goauth/src/config"
)

// SecretKeys is better-auth's secret configuration (ctx.context.secretConfig): either one secret (no `secrets`
// configured) or versioned secrets for rotation.
//
//   - Encrypt / EncodeJWE use the current secret. With versioned secrets Encrypt writes a "$ba$<version>$<hex>"
//     envelope, with a single secret bare hex (exactly like better-auth's symmetricEncrypt).
//   - Decrypt picks the secret named by the envelope version; bare hex is decrypted with Legacy (versioned) or
//     the single secret.
//   - DecodeJWE tries every secret (matching the JWE `kid` thumbprint), like symmetricDecodeJWT.
//   - VerifySecrets lists every secret a signature may have been made with (current first), so cookies signed
//     before a rotation still verify. better-auth only verifies cookie signatures with the current secret; this
//     is a goauth extension that keeps users signed in across a rotation.
type SecretKeys struct {
	// Current is the version that encrypts new data (the first entry of AuthConfig.Secrets).
	Current int
	// Keys maps version → secret. Empty means single-secret mode (Secret).
	Keys map[int]string
	// Legacy decrypts bare-hex payloads written before versioning (better-auth's legacySecret).
	Legacy string
	// Secret is the single secret used when Keys is empty (better-auth's string secretConfig).
	Secret string
}

// NewSecretKeys builds the secret configuration of conf: AuthConfig.Secrets when set (current = first entry,
// legacy = AuthConfig.LegacySecret()), else the single AuthConfig.Secret.
func NewSecretKeys(conf config.AuthConfig) SecretKeys {
	// Step 1: single-secret mode
	if len(conf.Secrets) == 0 {
		return SingleSecret(conf.Secret)
	}
	// Step 2: versioned secrets; the first entry is the current one
	keys := make(map[int]string, len(conf.Secrets))
	for _, s := range conf.Secrets {
		keys[s.Version] = s.Value
	}
	return SecretKeys{Current: conf.Secrets[0].Version, Keys: keys, Legacy: conf.LegacySecret()}
}

// SingleSecret returns the configuration for one secret (better-auth's secretConfig as a plain string).
func SingleSecret(secret string) SecretKeys { return SecretKeys{Secret: secret} }

// Versioned reports whether versioned secrets (rotation) are configured.
func (k SecretKeys) Versioned() bool { return len(k.Keys) > 0 }

// CurrentSecret returns the secret that signs and encrypts new data.
func (k SecretKeys) CurrentSecret() string {
	if k.Versioned() {
		return k.Keys[k.Current]
	}
	return k.Secret
}

// VerifySecrets returns every secret a signature or ciphertext may have been made with: the current secret,
// then the other versions (newest version first), then the legacy secret when it is not one of them.
// It is better-auth's getAllSecrets, ordered current-first.
func (k SecretKeys) VerifySecrets() []string {
	// Step 1: single-secret mode
	if !k.Versioned() {
		if k.Secret == "" {
			return nil
		}
		return []string{k.Secret}
	}
	// Step 2: current, then the older versions newest first
	out := []string{}
	if cur, ok := k.Keys[k.Current]; ok {
		out = append(out, cur)
	}
	versions := make([]int, 0, len(k.Keys))
	for v := range k.Keys {
		if v != k.Current {
			versions = append(versions, v)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(versions)))
	for _, v := range versions {
		out = append(out, k.Keys[v])
	}
	// Step 3: the legacy secret last, unless it is one of the versions
	if k.Legacy != "" {
		dup := false
		for _, s := range out {
			if s == k.Legacy {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, k.Legacy)
		}
	}
	return out
}

// Encrypt is better-auth's symmetricEncrypt({key: secretConfig}): a versioned "$ba$<version>$<hex>" envelope
// with rotation, bare hex with a single secret.
func (k SecretKeys) Encrypt(data string) (string, error) {
	// Step 1: single-secret mode writes bare hex
	if !k.Versioned() {
		if k.Secret == "" {
			return "", errors.New("authcrypto: no secret configured")
		}
		return SymmetricEncrypt(k.Secret, data)
	}
	// Step 2: the current version encrypts and is named in the envelope
	secret, ok := k.Keys[k.Current]
	if !ok {
		return "", fmt.Errorf("authcrypto: secret version %d not found", k.Current)
	}
	ct, err := SymmetricEncrypt(secret, data)
	if err != nil {
		return "", err
	}
	return envelopePrefix + strconv.Itoa(k.Current) + "$" + ct, nil
}

// Decrypt is better-auth's symmetricDecrypt({key: secretConfig}): envelopes are decrypted with the secret of
// their version (an unknown, e.g. retired, version fails), bare hex with Legacy (or the single secret).
func (k SecretKeys) Decrypt(data string) (string, error) {
	// Step 1: single-secret mode reads bare hex only, like better-auth's string key
	if !k.Versioned() {
		if k.Secret == "" {
			return "", errors.New("authcrypto: no secret configured")
		}
		return SymmetricDecrypt(k.Secret, data)
	}
	// Step 2: versioned envelope
	if version, ct, ok := parseEnvelope(data); ok {
		secret, found := k.Keys[version]
		if !found {
			return "", fmt.Errorf("authcrypto: secret version %d not found in keys (key may have been retired)", version)
		}
		return SymmetricDecrypt(secret, ct)
	}
	// Step 3: bare hex written before rotation
	if k.Legacy == "" {
		return "", errors.New("authcrypto: cannot decrypt legacy bare-hex payload: no legacy secret available")
	}
	return SymmetricDecrypt(k.Legacy, data)
}

// IsEnvelope reports whether data is a "$ba$<version>$..." envelope.
func IsEnvelope(data string) bool {
	_, _, ok := parseEnvelope(data)
	return ok
}
