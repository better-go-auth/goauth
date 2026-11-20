// Package eip4361 implements Sign-In with Ethereum messages (EIP-4361) and Ethereum personal_sign
// signatures (EIP-191) with secp256k1 public-key recovery: parsing and formatting SIWE messages, EIP-55
// checksum addresses, signing (for tests and server-side tools) and the signature check the siwe plugin
// uses as its default verifyMessage.
package eip4361

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Message is an EIP-4361 message.
type Message struct {
	// Scheme is the optional URI scheme of the origin ("https"); empty when the message has none.
	Scheme string
	// Domain is the RFC 3986 authority requesting the sign-in ("example.com", "localhost:3000").
	Domain string
	// Address is the Ethereum address performing the signing (0x + 40 hex digits).
	Address string
	// Statement is the optional human-readable assertion.
	Statement string
	// URI is the RFC 3986 URI referring to the resource that is the subject of the signing.
	URI string
	// Version is the message version; must be "1".
	Version string
	// ChainID is the EIP-155 chain id.
	ChainID int64
	// Nonce is the server-issued nonce (at least 8 alphanumeric characters).
	Nonce string
	// IssuedAt is the RFC 3339 issuance time.
	IssuedAt time.Time
	// ExpirationTime is the optional RFC 3339 time after which the message is invalid.
	ExpirationTime *time.Time
	// NotBefore is the optional RFC 3339 time before which the message is invalid.
	NotBefore *time.Time
	// RequestID is an optional system-specific identifier.
	RequestID string
	// Resources are optional URIs the user wishes to have resolved.
	Resources []string
}

// headerSuffix ends the first line of every SIWE message.
const headerSuffix = " wants you to sign in with your Ethereum account:"

var (
	headerRegex  = regexp.MustCompile(`^(?:([a-zA-Z][a-zA-Z0-9+.-]*)://)?(\S+) wants you to sign in with your Ethereum account:$`)
	addressRegex = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	fieldRegex   = regexp.MustCompile(`^([A-Za-z ]+): (.*)$`)
	nonceRegex   = regexp.MustCompile(`^[a-zA-Z0-9]{8,}$`)
)

// String formats the message like EIP-4361 (and viem's createSiweMessage).
func (m *Message) String() string {
	var b strings.Builder
	// Step 1: header, address and the optional statement
	origin := m.Domain
	if m.Scheme != "" {
		origin = m.Scheme + "://" + m.Domain
	}
	b.WriteString(origin + headerSuffix + "\n" + m.Address + "\n\n")
	if m.Statement != "" {
		b.WriteString(m.Statement + "\n")
	}
	// Step 2: the required fields
	version := m.Version
	if version == "" {
		version = "1"
	}
	issuedAt := m.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	fmt.Fprintf(&b, "\nURI: %s\nVersion: %s\nChain ID: %d\nNonce: %s\nIssued At: %s", m.URI, version, m.ChainID, m.Nonce, formatTime(issuedAt))
	// Step 3: the optional fields
	if m.ExpirationTime != nil {
		b.WriteString("\nExpiration Time: " + formatTime(*m.ExpirationTime))
	}
	if m.NotBefore != nil {
		b.WriteString("\nNot Before: " + formatTime(*m.NotBefore))
	}
	if m.RequestID != "" {
		b.WriteString("\nRequest ID: " + m.RequestID)
	}
	if len(m.Resources) > 0 {
		b.WriteString("\nResources:")
		for _, r := range m.Resources {
			b.WriteString("\n- " + r)
		}
	}
	return b.String()
}

// formatTime is JavaScript's Date.toISOString (UTC, milliseconds).
func formatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// Fields is the result of LooseParse: better-auth's parseSiweMessage, which reads whatever fields it
// finds without validating the message. Zero values mean "missing".
type Fields struct {
	Scheme, Domain, Address, URI, Version, Nonce, IssuedAt, ExpirationTime, NotBefore, RequestID string
	// ChainID is set when the "Chain ID" field holds an integer.
	ChainID    int64
	HasChainID bool
}

// LooseParse is better-auth's parseSiweMessage: the header line gives scheme and domain, the second line
// the address (when it is one), and every "Key: value" line the known fields (the last one wins).
func LooseParse(message string) Fields {
	var f Fields
	lines := strings.Split(strings.ReplaceAll(message, "\r\n", "\n"), "\n")
	// Step 1: header and address lines
	if m := headerRegex.FindStringSubmatch(lines[0]); m != nil {
		f.Scheme, f.Domain = m[1], m[2]
	}
	if len(lines) > 1 {
		if a := strings.TrimSpace(lines[1]); addressRegex.MatchString(a) {
			f.Address = a
		}
	}
	// Step 2: the fields
	for _, line := range lines {
		m := fieldRegex.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch m[1] {
		case "URI":
			f.URI = m[2]
		case "Version":
			f.Version = m[2]
		case "Chain ID":
			if n, ok := jsInteger(m[2]); ok {
				f.ChainID, f.HasChainID = n, true
			}
		case "Nonce":
			f.Nonce = m[2]
		case "Issued At":
			f.IssuedAt = m[2]
		case "Expiration Time":
			f.ExpirationTime = m[2]
		case "Not Before":
			f.NotBefore = m[2]
		case "Request ID":
			f.RequestID = m[2]
		}
	}
	return f
}

// jsInteger is Number.isInteger(Number(s)) for the decimal strings SIWE messages carry.
func jsInteger(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, true // Number("") is 0
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f == float64(int64(f)) {
		return int64(f), true
	}
	return 0, false
}

// NormalizeDomain is better-auth's normalizeSiweDomain: lower-cased host[:port] without scheme and path.
func NormalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	if i := strings.Index(d, "://"); i > 0 && isScheme(d[:i]) {
		d = d[i+3:]
	}
	if i := strings.Index(d, "/"); i >= 0 {
		d = d[:i]
	}
	return d
}

// isScheme reports whether s is an RFC 3986 scheme ([a-z][a-z0-9+.-]*).
func isScheme(s string) bool {
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-'):
		default:
			return false
		}
	}
	return s != ""
}

// ErrInvalidMessage wraps every ParseMessage failure.
var ErrInvalidMessage = errors.New("eip4361: invalid message")

// invalid builds a parse error.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidMessage, fmt.Sprintf(format, args...))
}

// ParseMessage parses a message strictly by the EIP-4361 grammar: header, address, blank line, optional
// statement, blank line, then URI, Version (1), Chain ID, Nonce (≥ 8 alphanumerics), Issued At and the
// optional Expiration Time, Not Before, Request ID and Resources, in this order.
func ParseMessage(message string) (*Message, error) {
	lines := strings.Split(strings.ReplaceAll(message, "\r\n", "\n"), "\n")
	m := &Message{}
	// Step 1: header and address
	h := headerRegex.FindStringSubmatch(lines[0])
	if h == nil {
		return nil, invalid("bad header line")
	}
	m.Scheme, m.Domain = h[1], h[2]
	if len(lines) < 4 || !addressRegex.MatchString(lines[1]) {
		return nil, invalid("bad address line")
	}
	m.Address = lines[1]
	if lines[2] != "" {
		return nil, invalid("missing blank line after the address")
	}
	// Step 2: the optional statement and the blank line before the fields
	i := 3
	if lines[i] != "" {
		if strings.HasPrefix(lines[i], "URI: ") {
			return nil, invalid("missing blank line before URI")
		}
		m.Statement = lines[i]
		i++
		if i >= len(lines) || lines[i] != "" {
			return nil, invalid("missing blank line after the statement")
		}
	}
	i++
	// Step 3: the fields, in grammar order
	next := func(key string, required bool) (string, error) {
		if i < len(lines) && strings.HasPrefix(lines[i], key+": ") {
			v := strings.TrimPrefix(lines[i], key+": ")
			i++
			return v, nil
		}
		if required {
			return "", invalid("missing %s", key)
		}
		return "", nil
	}
	var err error
	if m.URI, err = next("URI", true); err != nil {
		return nil, err
	}
	if m.Version, err = next("Version", true); err != nil {
		return nil, err
	}
	if m.Version != "1" {
		return nil, invalid("unsupported version %q", m.Version)
	}
	chain, err := next("Chain ID", true)
	if err != nil {
		return nil, err
	}
	if m.ChainID, err = strconv.ParseInt(chain, 10, 64); err != nil || m.ChainID <= 0 {
		return nil, invalid("bad chain id %q", chain)
	}
	if m.Nonce, err = next("Nonce", true); err != nil {
		return nil, err
	}
	if !nonceRegex.MatchString(m.Nonce) {
		return nil, invalid("nonce must be at least 8 alphanumeric characters")
	}
	issued, err := next("Issued At", true)
	if err != nil {
		return nil, err
	}
	if m.IssuedAt, err = parseTime(issued); err != nil {
		return nil, invalid("bad Issued At %q", issued)
	}
	// Step 4: optional fields
	if v, _ := next("Expiration Time", false); v != "" {
		t, err := parseTime(v)
		if err != nil {
			return nil, invalid("bad Expiration Time %q", v)
		}
		m.ExpirationTime = &t
	}
	if v, _ := next("Not Before", false); v != "" {
		t, err := parseTime(v)
		if err != nil {
			return nil, invalid("bad Not Before %q", v)
		}
		m.NotBefore = &t
	}
	m.RequestID, _ = next("Request ID", false)
	if i < len(lines) && lines[i] == "Resources:" {
		i++
		for i < len(lines) && strings.HasPrefix(lines[i], "- ") {
			m.Resources = append(m.Resources, strings.TrimPrefix(lines[i], "- "))
			i++
		}
	}
	// Step 5: nothing may follow
	if i != len(lines) {
		return nil, invalid("unexpected line %q", lines[i])
	}
	return m, nil
}

// parseTime parses an RFC 3339 date-time.
func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }
