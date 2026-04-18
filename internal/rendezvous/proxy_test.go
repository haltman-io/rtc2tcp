package rendezvous

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()

	t.Run("empty returns nil", func(t *testing.T) {
		got, err := ParseTrustedProxies("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("mixed list", func(t *testing.T) {
		got, err := ParseTrustedProxies("127.0.0.1, 10.0.0.0/8  2001:db8::/32")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(got))
		}
	})

	t.Run("invalid entry", func(t *testing.T) {
		if _, err := ParseTrustedProxies("not-an-ip"); err == nil {
			t.Fatal("expected error for invalid entry")
		}
	})
}

func newRequest(t *testing.T, remoteAddr string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func mustTrusted(t *testing.T, spec string) []trustedNet {
	t.Helper()
	n, err := ParseTrustedProxies(spec)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%q): %v", spec, err)
	}
	return n
}

func TestClientIP_NoTrustedProxies(t *testing.T) {
	t.Parallel()

	// Forwarded-For must be ignored when no upstream is trusted.
	r := newRequest(t, "203.0.113.9:44444", map[string]string{
		"X-Forwarded-For": "198.51.100.1",
	})
	got := clientIP(r, nil, "X-Forwarded-For")
	if got != "203.0.113.9" {
		t.Fatalf("expected direct IP, got %q", got)
	}
}

func TestClientIP_UntrustedDirectPeerIgnoresHeader(t *testing.T) {
	t.Parallel()

	trusted := mustTrusted(t, "10.0.0.0/8")
	r := newRequest(t, "203.0.113.9:44444", map[string]string{
		"X-Forwarded-For": "198.51.100.1",
	})
	got := clientIP(r, trusted, "X-Forwarded-For")
	if got != "203.0.113.9" {
		t.Fatalf("spoofed XFF from untrusted peer should be ignored; got %q", got)
	}
}

func TestClientIP_TrustedPeerHonoursXFF(t *testing.T) {
	t.Parallel()

	trusted := mustTrusted(t, "10.0.0.0/8")
	r := newRequest(t, "10.1.2.3:44444", map[string]string{
		"X-Forwarded-For": "198.51.100.1",
	})
	got := clientIP(r, trusted, "X-Forwarded-For")
	if got != "198.51.100.1" {
		t.Fatalf("expected XFF client IP, got %q", got)
	}
}

func TestClientIP_XFFStripsTrustedHops(t *testing.T) {
	t.Parallel()

	// Client 198.51.100.1 -> trusted edge 10.0.0.9 -> trusted internal 10.0.0.2 -> broker.
	// XFF chain built hop-by-hop: "client, edge, internal". The real
	// client is the leftmost untrusted entry.
	trusted := mustTrusted(t, "10.0.0.0/8")
	r := newRequest(t, "10.0.0.2:44444", map[string]string{
		"X-Forwarded-For": "198.51.100.1, 10.0.0.9, 10.0.0.2",
	})
	got := clientIP(r, trusted, "X-Forwarded-For")
	if got != "198.51.100.1" {
		t.Fatalf("expected leftmost untrusted IP, got %q", got)
	}
}

func TestClientIP_XFFAllTrustedFallsBack(t *testing.T) {
	t.Parallel()

	trusted := mustTrusted(t, "10.0.0.0/8")
	r := newRequest(t, "10.0.0.2:44444", map[string]string{
		"X-Forwarded-For": "10.0.0.9, 10.0.0.2",
	})
	got := clientIP(r, trusted, "X-Forwarded-For")
	if got != "10.0.0.2" {
		t.Fatalf("expected direct peer when every XFF entry is trusted, got %q", got)
	}
}

func TestClientIP_CloudflareHeader(t *testing.T) {
	t.Parallel()

	// Cloudflare Tunnel egress lives inside 127.0.0.1 when terminating
	// via cloudflared on the broker host.
	trusted := mustTrusted(t, "127.0.0.1")
	r := newRequest(t, "127.0.0.1:55555", map[string]string{
		"CF-Connecting-IP": "198.51.100.42",
	})
	got := clientIP(r, trusted, "CF-Connecting-IP")
	if got != "198.51.100.42" {
		t.Fatalf("expected CF-Connecting-IP, got %q", got)
	}
}

func TestClientIP_MissingHeaderFallsBack(t *testing.T) {
	t.Parallel()

	trusted := mustTrusted(t, "127.0.0.1")
	r := newRequest(t, "127.0.0.1:55555", nil)
	got := clientIP(r, trusted, "X-Forwarded-For")
	if got != "127.0.0.1" {
		t.Fatalf("expected direct peer when header missing, got %q", got)
	}
}
