package socks5_test

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/haltman-io/rtc2tcp/internal/socks5"
)

/* helpers that build SOCKS5 wire bytes so individual tests stay readable. */

func greeting(methods ...byte) []byte {
	return append([]byte{0x05, byte(len(methods))}, methods...)
}

func connectIPv4(ip net.IP, port uint16) []byte {
	b := []byte{0x05, 0x01, 0x00, 0x01}
	b = append(b, ip.To4()...)
	return append(b, byte(port>>8), byte(port))
}

func connectFQDN(domain string, port uint16) []byte {
	b := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	b = append(b, []byte(domain)...)
	return append(b, byte(port>>8), byte(port))
}

func connectIPv6(ip net.IP, port uint16) []byte {
	b := []byte{0x05, 0x01, 0x00, 0x04}
	b = append(b, ip.To16()...)
	return append(b, byte(port>>8), byte(port))
}

/* runClient drives the client side of the handshake on a net.Pipe so
Handshake can run on the server side synchronously in the test goroutine.
The greeting length is 2 + nMethods bytes; sending the full greeting before
reading the server's method selection avoids a deadlock when nMethods > 1. */
func runClient(t *testing.T, client net.Conn, send []byte) {
	t.Helper()
	go func() {
		defer client.Close()
		greetLen := 2 + int(send[1])
		if _, err := client.Write(send[:greetLen]); err != nil {
			return
		}
		// Read method selection response before sending the request.
		resp := make([]byte, 2)
		if _, err := io.ReadFull(client, resp); err != nil {
			return
		}
		if len(send) > greetLen {
			_, _ = client.Write(send[greetLen:])
		}
	}()
}

func TestHandshake_IPv4(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pkt := append(greeting(0x00), connectIPv4(net.ParseIP("1.2.3.4"), 80)...)
	runClient(t, client, pkt)

	target, err := socks5.Handshake(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "1.2.3.4:80" {
		t.Fatalf("target = %q, want 1.2.3.4:80", target)
	}
}

func TestHandshake_FQDN(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pkt := append(greeting(0x00), connectFQDN("example.com", 443)...)
	runClient(t, client, pkt)

	target, err := socks5.Handshake(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "example.com:443" {
		t.Fatalf("target = %q, want example.com:443", target)
	}
}

func TestHandshake_IPv6(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	ip := net.ParseIP("2001:db8::1")
	pkt := append(greeting(0x00), connectIPv6(ip, 22)...)
	runClient(t, client, pkt)

	target, err := socks5.Handshake(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "[2001:db8::1]:22" {
		t.Fatalf("target = %q, want [2001:db8::1]:22", target)
	}
}

func TestHandshake_MultipleMethodsIncludingNoAuth(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	// Offer username/password (0x02) AND no-auth (0x00).
	pkt := append(greeting(0x02, 0x00), connectFQDN("ifconfig.me", 80)...)
	runClient(t, client, pkt)

	if _, err := socks5.Handshake(server); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandshake_BadVersion(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		// SOCKS4 version byte.
		_, _ = client.Write([]byte{0x04, 0x01, 0x00})
	}()

	_, err := socks5.Handshake(server)
	if !errors.Is(err, socks5.ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestHandshake_NoAcceptableMethod(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		// Only offer username/password; no no-auth.
		_, _ = client.Write(greeting(0x02))
		// Server writes the no-accept byte; drain it so the write doesn't block.
		buf := make([]byte, 2)
		_, _ = io.ReadFull(client, buf)
	}()

	_, err := socks5.Handshake(server)
	if !errors.Is(err, socks5.ErrNoAcceptableMethod) {
		t.Fatalf("expected ErrNoAcceptableMethod, got %v", err)
	}
}

func TestHandshake_UnsupportedCommand(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	// BIND command (0x02) instead of CONNECT.
	pkt := append(greeting(0x00), []byte{0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50}...)
	runClient(t, client, pkt)

	_, err := socks5.Handshake(server)
	if !errors.Is(err, socks5.ErrUnsupportedCommand) {
		t.Fatalf("expected ErrUnsupportedCommand, got %v", err)
	}
}

func TestHandshake_UnsupportedAddressType(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	// Address type 0x02 is not defined by RFC 1928.
	pkt := append(greeting(0x00), []byte{0x05, 0x01, 0x00, 0x02, 0x00, 0x50}...)
	runClient(t, client, pkt)

	_, err := socks5.Handshake(server)
	if !errors.Is(err, socks5.ErrUnsupportedAddressType) {
		t.Fatalf("expected ErrUnsupportedAddressType, got %v", err)
	}
}

func TestReplySuccess(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 10)
		if _, err := io.ReadFull(client, buf); err == nil {
			done <- buf
		} else {
			done <- nil
		}
	}()

	if err := socks5.ReplySuccess(server); err != nil {
		t.Fatalf("ReplySuccess: %v", err)
	}

	reply := <-done
	if len(reply) != 10 {
		t.Fatalf("reply length = %d, want 10", len(reply))
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("reply VER/REP = %02x %02x, want 05 00", reply[0], reply[1])
	}
}

func TestReplyFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 10)
		if _, err := io.ReadFull(client, buf); err == nil {
			done <- buf
		} else {
			done <- nil
		}
	}()

	socks5.ReplyFailure(server)

	reply := <-done
	if len(reply) != 10 {
		t.Fatalf("reply length = %d, want 10", len(reply))
	}
	if reply[0] != 0x05 || reply[1] != 0x01 {
		t.Fatalf("reply VER/REP = %02x %02x, want 05 01", reply[0], reply[1])
	}
}
