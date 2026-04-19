// Package socks5 implements the server side of the SOCKS5 handshake
// (RFC 1928). Only the CONNECT command and the no-authentication method
// are supported; BIND and UDP ASSOCIATE are out of scope for a TCP tunnel.
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	version = 0x05

	cmdConnect = 0x01

	authNone     = 0x00
	authNoAccept = 0xFF

	addrTypeIPv4 = 0x01
	addrTypeFQDN = 0x03
	addrTypeIPv6 = 0x04

	replySuccess = 0x00
	replyFailure = 0x01
)

var (
	// ErrUnsupportedVersion is returned when the client speaks a SOCKS
	// version other than 5.
	ErrUnsupportedVersion = errors.New("unsupported SOCKS version")

	// ErrNoAcceptableMethod is returned when the client does not offer
	// the no-authentication method (0x00). We do not implement
	// username/password auth: the pairing secret already authenticates
	// the peer.
	ErrNoAcceptableMethod = errors.New("no acceptable auth method")

	// ErrUnsupportedCommand is returned for any command other than
	// CONNECT (0x01).
	ErrUnsupportedCommand = errors.New("unsupported SOCKS5 command")

	// ErrUnsupportedAddressType is returned for address types other
	// than IPv4, FQDN, and IPv6.
	ErrUnsupportedAddressType = errors.New("unsupported SOCKS5 address type")
)

// Handshake performs the server-side SOCKS5 negotiation on conn and
// returns the target address as "host:port". On success the caller must
// send a reply (ReplySuccess or ReplyFailure) before bridging. On error
// the caller should close conn; Handshake does not close it.
func Handshake(conn net.Conn) (string, error) {
	// Version identifier / method selection.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read version: %w", err)
	}
	if header[0] != version {
		return "", fmt.Errorf("%w: %d", ErrUnsupportedVersion, header[0])
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}

	if !hasMethod(methods, authNone) {
		_, _ = conn.Write([]byte{version, authNoAccept})
		return "", ErrNoAcceptableMethod
	}
	if _, err := conn.Write([]byte{version, authNone}); err != nil {
		return "", fmt.Errorf("write method selection: %w", err)
	}

	// Request.
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", fmt.Errorf("read request: %w", err)
	}
	if req[0] != version {
		return "", fmt.Errorf("%w: %d", ErrUnsupportedVersion, req[0])
	}
	if req[1] != cmdConnect {
		return "", fmt.Errorf("%w: 0x%02x", ErrUnsupportedCommand, req[1])
	}
	// req[2] is RSV, ignored.

	host, err := readAddr(conn, req[3])
	if err != nil {
		return "", err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// ReplySuccess sends the SOCKS5 success reply (X'00'). Call this only
// after the target dial succeeds; send it before starting the bridge so
// the client knows the connection is live.
func ReplySuccess(conn net.Conn) error {
	// BND.ADDR and BND.PORT are all-zero: we are a relay, not a direct
	// TCP proxy, so the bound address is not meaningful.
	_, err := conn.Write([]byte{version, replySuccess, 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// ReplyFailure sends the SOCKS5 general failure reply (X'01'). Always
// call this before closing conn on a dial error so the client sees a
// clean rejection instead of an abrupt close.
func ReplyFailure(conn net.Conn) {
	_, _ = conn.Write([]byte{version, replyFailure, 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0})
}

// readAddr reads the address field based on the SOCKS5 address type byte.
func readAddr(conn net.Conn, addrType byte) (string, error) {
	switch addrType {
	case addrTypeIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("read IPv4 addr: %w", err)
		}
		return net.IP(buf).String(), nil

	case addrTypeFQDN:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		return string(domain), nil

	case addrTypeIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("read IPv6 addr: %w", err)
		}
		return net.IP(buf).String(), nil

	default:
		return "", fmt.Errorf("%w: 0x%02x", ErrUnsupportedAddressType, addrType)
	}
}

func hasMethod(methods []byte, want byte) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}
