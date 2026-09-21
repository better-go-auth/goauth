package helpers

import (
	"net/url"
	"strings"
	"sync"

	"github.com/better-go-auth/goauth/src/config"
)

var _ config.VerificationSender = (*MockEmailSender)(nil)

type MockEmailSender struct {
	VerificationURLs  chan string
	PasswordResetURLs chan string
	OrgInvitationURLs chan string
	MagicLinkURLs     chan string

	mu               sync.Mutex
	lastTokenByEmail map[string]string
}

func NewMockEmailSender() *MockEmailSender {
	return &MockEmailSender{
		VerificationURLs:  make(chan string, 10),
		PasswordResetURLs: make(chan string, 10),
		OrgInvitationURLs: make(chan string, 10),
		MagicLinkURLs:     make(chan string, 10),
		lastTokenByEmail:  make(map[string]string),
	}
}

func (m *MockEmailSender) SendVerificationCode(to, code string) error {
	m.recordToken(to, code)
	m.VerificationURLs <- code
	return nil
}

func (m *MockEmailSender) LastToken(email string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, ok := m.lastTokenByEmail[normalizeEmail(email)]
	return token, ok
}

func (m *MockEmailSender) recordToken(email, raw string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token := raw
	if parsed, err := url.Parse(raw); err == nil {
		if q := parsed.Query().Get("token"); q != "" {
			token = q
		}
	}
	m.lastTokenByEmail[normalizeEmail(email)] = token
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
