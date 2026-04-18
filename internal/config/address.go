package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AddressRole selects the validation policy for ValidateAddress.
type AddressRole int

const (
	// AddressRoleTarget is for the expose-side `--target`. The host may
	// be a hostname (resolution is deferred to dial time) or an IP
	// literal; unspecified and multicast IP literals are rejected.
	AddressRoleTarget AddressRole = iota

	// AddressRoleListen is for the connect-side `--listen`. The host
	// must be an IP literal; unspecified and multicast addresses are
	// rejected so an operator does not accidentally expose the local
	// tunnel endpoint on every interface without meaning to.
	AddressRoleListen
)

// ValidateAddress parses `host:port` and rejects footguns: unspecified,
// multicast, and (for listen) non-IP hosts. Hostnames are allowed for
// the target role because dial-time resolution is fine. Returns the
// canonicalized address on success.
func ValidateAddress(addr string, role AddressRole) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("address is empty")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("parse address %q: %w", addr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid port %q", portStr)
	}

	if host == "" {
		return "", errors.New("host is empty")
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return "", fmt.Errorf("unspecified address %q is not allowed; name a specific interface", addr)
		}
		if ip.IsMulticast() {
			return "", fmt.Errorf("multicast address %q is not allowed", addr)
		}
		return net.JoinHostPort(ip.String(), portStr), nil
	}

	// host is not an IP literal
	if role == AddressRoleListen {
		return "", fmt.Errorf("listen address %q must be an IP literal", addr)
	}
	return addr, nil
}
