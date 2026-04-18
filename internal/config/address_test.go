package config

import (
	"strings"
	"testing"
)

func TestValidateAddressTargetAcceptsIPLiteral(t *testing.T) {
	got, err := ValidateAddress("127.0.0.1:22", AddressRoleTarget)
	if err != nil {
		t.Fatalf("ValidateAddress: %v", err)
	}
	if got != "127.0.0.1:22" {
		t.Fatalf("unexpected canonical form %q", got)
	}
}

func TestValidateAddressTargetAcceptsHostname(t *testing.T) {
	got, err := ValidateAddress("example.internal:443", AddressRoleTarget)
	if err != nil {
		t.Fatalf("ValidateAddress: %v", err)
	}
	if got != "example.internal:443" {
		t.Fatalf("unexpected canonical form %q", got)
	}
}

func TestValidateAddressTargetRejectsUnspecified(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:22", "[::]:22"} {
		if _, err := ValidateAddress(addr, AddressRoleTarget); err == nil || !strings.Contains(err.Error(), "unspecified") {
			t.Fatalf("%q: expected unspecified rejection, got %v", addr, err)
		}
	}
}

func TestValidateAddressTargetRejectsMulticast(t *testing.T) {
	for _, addr := range []string{"224.0.0.1:22", "[ff02::1]:22"} {
		if _, err := ValidateAddress(addr, AddressRoleTarget); err == nil || !strings.Contains(err.Error(), "multicast") {
			t.Fatalf("%q: expected multicast rejection, got %v", addr, err)
		}
	}
}

func TestValidateAddressListenRequiresIPLiteral(t *testing.T) {
	if _, err := ValidateAddress("example.internal:2222", AddressRoleListen); err == nil {
		t.Fatal("expected listen hostname to be rejected")
	}
}

func TestValidateAddressListenAcceptsLoopback(t *testing.T) {
	if _, err := ValidateAddress("127.0.0.1:2222", AddressRoleListen); err != nil {
		t.Fatalf("ValidateAddress: %v", err)
	}
	if _, err := ValidateAddress("[::1]:2222", AddressRoleListen); err != nil {
		t.Fatalf("ValidateAddress ipv6: %v", err)
	}
}

func TestValidateAddressRejectsBadPort(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "127.0.0.1:-1", "127.0.0.1:99999", "127.0.0.1:not-a-port"} {
		if _, err := ValidateAddress(addr, AddressRoleTarget); err == nil {
			t.Fatalf("%q: expected port rejection", addr)
		}
	}
}

func TestValidateAddressRejectsEmpty(t *testing.T) {
	if _, err := ValidateAddress("", AddressRoleTarget); err == nil {
		t.Fatal("expected empty address rejection")
	}
	if _, err := ValidateAddress("   ", AddressRoleListen); err == nil {
		t.Fatal("expected whitespace-only address rejection")
	}
}

func TestPeerOptionsValidateRejectsWildcardListen(t *testing.T) {
	opts := PeerOptions{
		Mode:            ModeConnect,
		RendezvousToken: "tok",
		PairingSecret:   "secret",
		BrokerURL:       "http://127.0.0.1:8080",
		Listen:          "0.0.0.0:2222",
	}
	if err := opts.Validate(); err == nil {
		t.Fatal("expected wildcard listen rejection")
	}
}

func TestPeerOptionsValidateRejectsMulticastTarget(t *testing.T) {
	opts := PeerOptions{
		Mode:            ModeExpose,
		RendezvousToken: "tok",
		PairingSecret:   "secret",
		BrokerURL:       "http://127.0.0.1:8080",
		Target:          "224.0.0.1:22",
	}
	if err := opts.Validate(); err == nil {
		t.Fatal("expected multicast target rejection")
	}
}
