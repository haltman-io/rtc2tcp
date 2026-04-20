// Package httpconnect implements the server side of the HTTP CONNECT
// tunneling method (RFC 7231 §4.3.6). Only the CONNECT method is
// supported; all other HTTP methods are rejected. The client is
// expected to wait for the 200 response before sending payload bytes,
// so no extra buffering is needed after headers are consumed.
package httpconnect

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	// ErrUnsupportedMethod is returned when the client sends any HTTP
	// method other than CONNECT.
	ErrUnsupportedMethod = errors.New("unsupported HTTP method")

	// ErrMalformedRequest is returned when the request line cannot be
	// parsed as "CONNECT host:port HTTP/x.y".
	ErrMalformedRequest = errors.New("malformed HTTP CONNECT request")
)

// Handshake reads an HTTP CONNECT request from conn and returns the
// target address as "host:port". On success the caller must send a
// reply (ReplySuccess or ReplyFailure) before bridging. On error the
// caller should close conn; Handshake does not close it.
func Handshake(conn net.Conn) (string, error) {
	r := bufio.NewReader(conn)

	// Request line: CONNECT host:port HTTP/1.x
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read request line: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")

	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: %q", ErrMalformedRequest, line)
	}
	if parts[0] != "CONNECT" {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedMethod, parts[0])
	}
	target := parts[1]
	if _, _, err := net.SplitHostPort(target); err != nil {
		return "", fmt.Errorf("%w: invalid target %q", ErrMalformedRequest, target)
	}

	// Drain headers until the blank line that ends the request.
	for {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read headers: %w", err)
		}
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
	}

	return target, nil
}

// ReplySuccess sends the HTTP 200 Connection established response.
// Call this after the target dial succeeds, before starting the
// bridge, so the client knows the connection is live.
func ReplySuccess(conn net.Conn) error {
	_, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	return err
}

// ReplyFailure sends the HTTP 502 Bad Gateway response. Call this
// before closing conn on a dial error so the client sees a clean
// rejection instead of an abrupt close.
func ReplyFailure(conn net.Conn) {
	_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
}
