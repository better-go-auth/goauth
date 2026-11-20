package services

import (
	"net/netip"
	"strings"
)

// cloudMetadataHosts are cloud instance-metadata FQDNs (better-auth's CLOUD_METADATA_HOSTS).
var cloudMetadataHosts = map[string]bool{
	"metadata.google.internal":   true,
	"metadata.goog":              true,
	"metadata":                   true,
	"instance-data":              true,
	"instance-data.ec2.internal": true,
}

// hostKind is better-auth's classifyHost result: the kind plus whether the host is an IP literal.
type hostKind struct {
	kind    string
	literal string // "ipv4", "ipv6" or "fqdn"
}

// stripPort removes ":port" from "host:port" and "[v6]:port" (bare IPv6 is left alone).
func stripPort(host string) string {
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end != -1 {
			return host[:end+1]
		}
		return host
	}
	first := strings.Index(host, ":")
	if first == -1 || strings.Contains(host[first+1:], ":") {
		return host
	}
	return host[:first]
}

// classifyHost is better-auth's classifyHost (@better-auth/core/utils/host, RFC 6890 / RFC 6761).
func classifyHost(host string) hostKind {
	// Step 1: normalize: port, brackets, zone id, trailing dots, case
	h := stripPort(strings.TrimSpace(host))
	if len(h) >= 2 && strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if i := strings.Index(h, "%"); i != -1 {
		h = h[:i]
	}
	h = strings.ToLower(strings.TrimRight(h, "."))
	if h == "" {
		return hostKind{kind: "reserved", literal: "fqdn"}
	}
	// Step 2: names
	addr, err := netip.ParseAddr(h)
	if err != nil {
		switch {
		case h == "localhost" || strings.HasSuffix(h, ".localhost"):
			return hostKind{kind: "localhost", literal: "fqdn"}
		case cloudMetadataHosts[h]:
			return hostKind{kind: "cloudMetadata", literal: "fqdn"}
		}
		return hostKind{kind: "public", literal: "fqdn"}
	}
	// Step 3: IPv4 (including IPv4-mapped IPv6)
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		return hostKind{kind: classifyIPv4(addr), literal: "ipv4"}
	}
	return hostKind{kind: classifyIPv6(addr), literal: "ipv6"}
}

// v4 ranges in better-auth's order.
var v4Ranges = []struct {
	prefix netip.Prefix
	kind   string
}{
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private"},
	{netip.MustParsePrefix("169.254.0.0/16"), "linkLocal"},
	{netip.MustParsePrefix("100.64.0.0/10"), "sharedAddressSpace"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("0.0.0.0/8"), "reserved"},
	{netip.MustParsePrefix("192.0.0.0/24"), "reserved"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},
}

func classifyIPv4(a netip.Addr) string {
	switch a.String() {
	case "0.0.0.0":
		return "unspecified"
	case "255.255.255.255":
		return "broadcast"
	}
	for _, r := range v4Ranges {
		if r.prefix.Contains(a) {
			return r.kind
		}
	}
	return "public"
}

// embeddedV4 returns the IPv4 stored in bytes [i, i+4) of a, XORed with 0xffffffff when xor (Teredo).
func embeddedV4(a netip.Addr, i int, xor bool) netip.Addr {
	b := a.As16()
	var v [4]byte
	copy(v[:], b[i:i+4])
	if xor {
		for k := range v {
			v[k] ^= 0xff
		}
	}
	return netip.AddrFrom4(v)
}

func classifyIPv6(a netip.Addr) string {
	b := a.As16()
	switch {
	case a.IsUnspecified():
		return "unspecified"
	case a.IsLoopback():
		return "loopback"
	case b[0] == 0xff:
		return "multicast"
	case b[0] == 0xfe && b[1]&0xc0 == 0x80:
		return "linkLocal"
	case b[0]&0xfe == 0xfc:
		return "private"
	case b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8:
		return "documentation"
	case b[0] == 0x20 && b[1] == 0x02:
		// 6to4: the embedded IPv4 must be public
		if classifyIPv4(embeddedV4(a, 2, false)) != "public" {
			return "reserved"
		}
		return "public"
	case netip.MustParsePrefix("64:ff9b::/96").Contains(a):
		return "reserved"
	case b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0:
		// Teredo
		return "reserved"
	case netip.MustParsePrefix("100::/64").Contains(a):
		return "reserved"
	}
	return "public"
}

// isPublicRoutableHost is better-auth's isPublicRoutableHost.
func isPublicRoutableHost(host string) bool { return classifyHost(host).kind == "public" }
