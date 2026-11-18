// Package services implements the have-i-been-pwned check: a k-anonymity lookup of the password's SHA-1
// hash in the Pwned Passwords range API, run before a configured endpoint hashes a new password.
package services

import (
	"context"
	"crypto/sha1" //nolint:gosec // the Pwned Passwords range API is keyed by SHA-1
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	hibpconfig "github.com/better-go-auth/goauth/src/plugins/haveibeenpwned/config"
)

// Error code and message of a compromised password (better-auth's ERROR_CODES).
const (
	CodePasswordCompromised = "PASSWORD_COMPROMISED"
	MsgPasswordCompromised  = "The password you entered has been compromised. Please choose a different password."
	// MsgCheckFailed is the message when the range API cannot be reached.
	MsgCheckFailed = "Failed to check password. Please try again later."
)

// Request headers sent to the range API (better-auth's).
const (
	userAgent = "BetterAuth Password Checker"
)

// Service checks passwords against the Pwned Passwords range API.
type Service struct {
	cfg      hibpconfig.HaveIBeenPwnedConfig
	basePath string
}

// New builds the service; basePath is the auth BasePath (default "/api/auth").
func New(cfg hibpconfig.HaveIBeenPwnedConfig, basePath string) *Service {
	basePath = strings.TrimSuffix(basePath, "/")
	if basePath == "" {
		basePath = "/api/auth"
	}
	return &Service{cfg: cfg.WithDefaults(), basePath: basePath}
}

// Config returns the effective configuration.
func (s *Service) Config() hibpconfig.HaveIBeenPwnedConfig { return s.cfg }

// BeforeHash is the password-hash hook (better-auth's wrapped ctx.password.hash): on the configured paths it
// checks the new password and fails the request when it is compromised. Outside HTTP requests (no request
// in ctx, like better-auth without an endpoint context) and on other paths it does nothing.
func (s *Service) BeforeHash(ctx context.Context, password string) error {
	// Step 1: the plugin can be switched off
	if !s.cfg.IsEnabled() {
		return nil
	}
	// Step 2: only the configured endpoint paths
	req := config.GetHTTPRequest(ctx)
	if req == nil || req.URL == nil {
		return nil
	}
	path := strings.TrimPrefix(req.URL.Path, s.basePath)
	if path == "" || !slices.Contains(s.cfg.Paths, path) {
		return nil
	}
	// Step 3: the k-anonymity lookup
	return s.CheckPassword(ctx, password)
}

// CheckPassword is better-auth's checkPasswordCompromise: it sends the first five characters of the
// password's upper-case SHA-1 hex digest to the range API and looks for the remaining 35 in the answer.
// A match is 400 PASSWORD_COMPROMISED (or CustomPasswordCompromisedMessage); an error status of the API is
// 500 "Failed to check password. Status: <status>", any other failure 500 MsgCheckFailed. An empty
// password is not checked.
func (s *Service) CheckPassword(ctx context.Context, password string) error {
	if password == "" {
		return nil
	}
	// Step 1: SHA-1 prefix and suffix
	sum := sha1.Sum([]byte(password)) //nolint:gosec // required by the range API
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]
	// Step 2: ask the range API (padded responses hide the number of matches)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.APIURL+prefix, nil)
	if err != nil {
		return checkFailed()
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return checkFailed()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return autherr.New("INTERNAL_SERVER_ERROR", fmt.Sprintf("Failed to check password. Status: %d", resp.StatusCode),
			http.StatusInternalServerError)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return checkFailed()
	}
	// Step 3: every line is "<SUFFIX>:<count>"; padding lines have count 0 and never match a real suffix
	for _, line := range strings.Split(string(body), "\n") {
		candidate, _, _ := strings.Cut(line, ":")
		if strings.EqualFold(candidate, suffix) {
			msg := s.cfg.CustomPasswordCompromisedMessage
			if msg == "" {
				msg = MsgPasswordCompromised
			}
			return autherr.New(CodePasswordCompromised, msg, http.StatusBadRequest)
		}
	}
	return nil
}

func checkFailed() error {
	return autherr.New("INTERNAL_SERVER_ERROR", MsgCheckFailed, http.StatusInternalServerError)
}
