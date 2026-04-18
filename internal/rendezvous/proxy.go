package rendezvous

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// trustedNet describes a single trusted upstream: either a specific IP
// or a CIDR block. It is used to decide whether forwarded-for headers
// from a given peer should be trusted.
type trustedNet struct {
	ipNet *net.IPNet
}

func (t trustedNet) contains(ip net.IP) bool {
	if ip == nil || t.ipNet == nil {
		return false
	}
	return t.ipNet.Contains(ip)
}

// ParseTrustedProxies parses a list of comma- or whitespace-separated
// IPs and CIDR blocks into a slice of trusted networks. Plain IPs are
// normalised to host-width CIDRs (/32 or /128). The empty string
// returns a nil slice, meaning "trust no upstream".
func ParseTrustedProxies(spec string) ([]trustedNet, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})

	out := make([]trustedNet, 0, len(fields))
	for _, raw := range fields {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", entry, err)
			}
			out = append(out, trustedNet{ipNet: ipNet})
			continue
		}

		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("trusted proxy %q: not a valid IP or CIDR", entry)
		}
		mask := 32
		if ip.To4() == nil {
			mask = 128
		}
		_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), mask))
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", entry, err)
		}
		out = append(out, trustedNet{ipNet: ipNet})
	}

	return out, nil
}

// isTrusted reports whether ip falls inside any of the configured
// trusted networks.
func isTrusted(ip net.IP, trusted []trustedNet) bool {
	for _, t := range trusted {
		if t.contains(ip) {
			return true
		}
	}
	return false
}

// clientIP resolves the effective client IP for r, honouring the
// broker's trusted-proxy configuration.
//
// Precedence:
//  1. If r.RemoteAddr is not in any trusted network, the direct remote
//     IP is returned verbatim and forwarded-for headers are ignored.
//     This prevents untrusted clients from spoofing a source IP.
//  2. If the direct peer is trusted and header is "X-Forwarded-For",
//     the rightmost entry whose IP is *not* itself a trusted proxy is
//     returned. This is the standard XFF hop-stripping rule: each
//     trusted hop is peeled away until the first untrusted address
//     (the real client) is found.
//  3. If the direct peer is trusted and header is any other name
//     (typically "X-Real-IP" or "CF-Connecting-IP"), the raw single
//     value is returned. These headers are always single-value, so no
//     list walking is performed.
//  4. If the configured header is absent or unparseable, the direct
//     remote IP is returned as a safe fallback.
//
// The returned string is an IP literal (no port).
func clientIP(r *http.Request, trusted []trustedNet, header string) string {
	direct := remoteIP(r)
	if len(trusted) == 0 || header == "" {
		return direct
	}

	directIP := net.ParseIP(direct)
	if directIP == nil || !isTrusted(directIP, trusted) {
		return direct
	}

	if strings.EqualFold(header, "X-Forwarded-For") {
		values := r.Header.Values(header)
		if len(values) == 0 {
			return direct
		}
		joined := strings.Join(values, ",")
		parts := strings.Split(joined, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if candidate == "" {
				continue
			}
			ip := net.ParseIP(candidate)
			if ip == nil {
				continue
			}
			if !isTrusted(ip, trusted) {
				return ip.String()
			}
		}
		return direct
	}

	value := strings.TrimSpace(r.Header.Get(header))
	if value == "" {
		return direct
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return direct
}
