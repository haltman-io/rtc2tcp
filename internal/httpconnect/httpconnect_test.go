package httpconnect_test

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/haltman-io/rtc2tcp/internal/httpconnect"
)

/* buildRequest assembles a minimal HTTP CONNECT request with the given
method, target, and a Host header so tests don't have to format it each time. */
func buildRequest(method, target string) []byte {
	return []byte(method + " " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
}

func TestHandshake_FQDN(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		_, _ = client.Write(buildRequest("CONNECT", "example.com:443"))
	}()

	target, err := httpconnect.Handshake(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "example.com:443" {
		t.Fatalf("target = %q, want example.com:443", target)
	}
}

func TestHandshake_IPv4(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		_, _ = client.Write(buildRequest("CONNECT", "1.2.3.4:80"))
	}()

	target, err := httpconnect.Handshake(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "1.2.3.4:80" {
		t.Fatalf("target = %q, want 1.2.3.4:80", target)
	}
}

func TestHandshake_IPv6(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		_, _ = client.Write(buildRequest("CONNECT", "[2001:db8::1]:22"))
	}()

	target, err := httpconnect.Handshake(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "[2001:db8::1]:22" {
		t.Fatalf("target = %q, want [2001:db8::1]:22", target)
	}
}

func TestHandshake_ExtraHeaders(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		req := "CONNECT example.com:80 HTTP/1.1\r\n" +
			"Host: example.com:80\r\n" +
			"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" +
			"User-Agent: curl/8.0\r\n" +
			"\r\n"
		_, _ = client.Write([]byte(req))
	}()

	target, err := httpconnect.Handshake(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "example.com:80" {
		t.Fatalf("target = %q, want example.com:80", target)
	}
}

func TestHandshake_UnsupportedMethod(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		_, _ = client.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	_, err := httpconnect.Handshake(server)
	if !errors.Is(err, httpconnect.ErrUnsupportedMethod) {
		t.Fatalf("expected ErrUnsupportedMethod, got %v", err)
	}
}

func TestHandshake_MalformedRequestLine(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		_, _ = client.Write([]byte("CONNECT\r\n\r\n"))
	}()

	_, err := httpconnect.Handshake(server)
	if !errors.Is(err, httpconnect.ErrMalformedRequest) {
		t.Fatalf("expected ErrMalformedRequest, got %v", err)
	}
}

func TestHandshake_InvalidTarget(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		defer client.Close()
		// Target has no port — net.SplitHostPort will reject it.
		_, _ = client.Write([]byte("CONNECT example.com HTTP/1.1\r\n\r\n"))
	}()

	_, err := httpconnect.Handshake(server)
	if !errors.Is(err, httpconnect.ErrMalformedRequest) {
		t.Fatalf("expected ErrMalformedRequest, got %v", err)
	}
}

func TestReplySuccess(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := client.Read(buf)
		done <- buf[:n]
	}()

	if err := httpconnect.ReplySuccess(server); err != nil {
		t.Fatalf("ReplySuccess: %v", err)
	}

	reply := <-done
	const want = "HTTP/1.1 200 Connection established\r\n\r\n"
	if string(reply) != want {
		t.Fatalf("reply = %q, want %q", reply, want)
	}
}

func TestReplyFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := client.Read(buf)
		done <- buf[:n]
	}()

	httpconnect.ReplyFailure(server)

	reply := <-done
	const want = "HTTP/1.1 502 Bad Gateway\r\n\r\n"
	if string(reply) != want {
		t.Fatalf("reply = %q, want %q", reply, want)
	}
}

// TestHandshake_ConnectionClosed verifies that a premature close returns
// a wrapped error rather than hanging.
func TestHandshake_ConnectionClosed(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		client.Close()
	}()

	_, err := httpconnect.Handshake(server)
	if err == nil {
		t.Fatal("expected error on closed connection, got nil")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		// Either EOF or pipe-closed is acceptable; just not nil.
		t.Logf("error (expected): %v", err)
	}
}
