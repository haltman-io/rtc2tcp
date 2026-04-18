package config

import (
	"strings"
	"testing"
)

func TestParseConnectionStringLoopback(t *testing.T) {
	cs, err := ParseConnectionString("rtc2tcp://tok:sec@127.0.0.1:8080/")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cs.RendezvousToken != "tok" || cs.PairingSecret != "sec" {
		t.Fatalf("token/secret = %q / %q", cs.RendezvousToken, cs.PairingSecret)
	}
	if cs.BrokerURL != "http://127.0.0.1:8080" {
		t.Fatalf("broker URL = %q, want http://127.0.0.1:8080", cs.BrokerURL)
	}
}

func TestParseConnectionStringRemoteUsesHTTPS(t *testing.T) {
	cs, err := ParseConnectionString("rtc2tcp://tok:sec@broker.example.com/")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cs.BrokerURL != "https://broker.example.com" {
		t.Fatalf("broker URL = %q, want https://broker.example.com", cs.BrokerURL)
	}
}

func TestParseConnectionStringEncodedValues(t *testing.T) {
	cs, err := ParseConnectionString("rtc2tcp://tok%20with%20space:sec%40bang@127.0.0.1:8080/")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cs.RendezvousToken != "tok with space" {
		t.Fatalf("token = %q", cs.RendezvousToken)
	}
	if cs.PairingSecret != "sec@bang" {
		t.Fatalf("secret = %q", cs.PairingSecret)
	}
}

func TestParseConnectionStringRejectsWrongScheme(t *testing.T) {
	if _, err := ParseConnectionString("http://tok:sec@host/"); err == nil {
		t.Fatal("expected scheme rejection")
	}
}

func TestParseConnectionStringRejectsMissingToken(t *testing.T) {
	if _, err := ParseConnectionString("rtc2tcp://127.0.0.1:8080/"); err == nil {
		t.Fatal("expected missing-token rejection")
	}
}

func TestParseConnectionStringRejectsMissingSecret(t *testing.T) {
	if _, err := ParseConnectionString("rtc2tcp://tok@127.0.0.1:8080/"); err == nil {
		t.Fatal("expected missing-secret rejection")
	}
}

func TestParseConnectionStringRejectsEmpty(t *testing.T) {
	if _, err := ParseConnectionString(""); err == nil {
		t.Fatal("expected empty-string rejection")
	}
	if _, err := ParseConnectionString("   "); err == nil {
		t.Fatal("expected whitespace-only rejection")
	}
}

func TestConnectionStringFormatRoundTrip(t *testing.T) {
	original := ConnectionString{
		RendezvousToken: "AbCdEf-123",
		PairingSecret:   "xYz_098",
		BrokerURL:       "http://127.0.0.1:8080",
	}
	s, err := original.Format()
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	parsed, err := ParseConnectionString(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	if *parsed != original {
		t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v", *parsed, original)
	}
}

func TestConnectionStringFormatEscapesSpecials(t *testing.T) {
	cs := ConnectionString{
		RendezvousToken: "tok with space",
		PairingSecret:   "sec@bang",
		BrokerURL:       "http://127.0.0.1:8080",
	}
	s, err := cs.Format()
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.Contains(s, " ") {
		t.Fatalf("unescaped space in formatted string: %q", s)
	}
	parsed, err := ParseConnectionString(s)
	if err != nil {
		t.Fatalf("round trip Parse(%q): %v", s, err)
	}
	if parsed.RendezvousToken != cs.RendezvousToken || parsed.PairingSecret != cs.PairingSecret {
		t.Fatalf("round trip drift:\n got: %+v\nwant: %+v", *parsed, cs)
	}
}

func TestConnectionStringFormatDropsWsPath(t *testing.T) {
	cs := ConnectionString{
		RendezvousToken: "tok",
		PairingSecret:   "sec",
		BrokerURL:       "http://127.0.0.1:8080/ws",
	}
	s, err := cs.Format()
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.HasSuffix(s, "/ws") {
		t.Fatalf("/ws path should be dropped, got %q", s)
	}
}

func TestRandomTokenLengthIsStable(t *testing.T) {
	a, err := RandomToken()
	if err != nil {
		t.Fatalf("RandomToken: %v", err)
	}
	b, err := RandomToken()
	if err != nil {
		t.Fatalf("RandomToken: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("token length varies: %d vs %d", len(a), len(b))
	}
	if a == b {
		t.Fatal("two RandomToken() calls returned the same value")
	}
	// 16 bytes -> ceil(16*4/3) = 22 base64url chars.
	if len(a) != 22 {
		t.Fatalf("unexpected token length %d", len(a))
	}
}
