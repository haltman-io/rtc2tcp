package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"rtc2tcp/internal/config"
)

func initiatorMaterial() SessionBindingMaterial {
	return SessionBindingMaterial{
		SessionID:         "session-1",
		Mode:              config.ModeConnect,
		LocalFingerprint:  "SHA-256 AA:BB",
		RemoteFingerprint: "SHA-256 CC:DD",
	}
}

func responderMaterial() SessionBindingMaterial {
	return SessionBindingMaterial{
		SessionID:         "session-1",
		Mode:              config.ModeExpose,
		LocalFingerprint:  "SHA-256 CC:DD",
		RemoteFingerprint: "SHA-256 AA:BB",
	}
}

func mustNewAuth(t *testing.T, secret string) *InteractiveAuthenticator {
	t.Helper()
	a, err := NewInteractiveAuthenticator(secret)
	if err != nil {
		t.Fatalf("NewInteractiveAuthenticator: %v", err)
	}
	return a
}

func bindPair(t *testing.T, secret string) (*InteractiveAuthenticator, *InteractiveAuthenticator) {
	t.Helper()
	initiator := mustNewAuth(t, secret)
	responder := mustNewAuth(t, secret)
	if err := initiator.Bind(initiatorMaterial()); err != nil {
		t.Fatalf("Bind(init): %v", err)
	}
	if err := responder.Bind(responderMaterial()); err != nil {
		t.Fatalf("Bind(resp): %v", err)
	}
	return initiator, responder
}

func runHandshake(t *testing.T, initiator, responder *InteractiveAuthenticator) {
	t.Helper()

	hello, err := initiator.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if hello.Kind != MessageKindHello {
		t.Fatalf("expected hello, got %q", hello.Kind)
	}

	accept, hasOutbound, done, err := responder.Step(hello)
	if err != nil {
		t.Fatalf("responder Step(hello): %v", err)
	}
	if !hasOutbound || done {
		t.Fatalf("responder expected (hasOutbound=true, done=false), got (%v, %v)", hasOutbound, done)
	}
	if accept.Kind != MessageKindAccept {
		t.Fatalf("expected accept, got %q", accept.Kind)
	}

	confirm, hasOutbound, done, err := initiator.Step(accept)
	if err != nil {
		t.Fatalf("initiator Step(accept): %v", err)
	}
	if !hasOutbound || !done {
		t.Fatalf("initiator expected (hasOutbound=true, done=true), got (%v, %v)", hasOutbound, done)
	}
	if confirm.Kind != MessageKindConfirm {
		t.Fatalf("expected confirm, got %q", confirm.Kind)
	}

	_, hasOutbound, done, err = responder.Step(confirm)
	if err != nil {
		t.Fatalf("responder Step(confirm): %v", err)
	}
	if hasOutbound || !done {
		t.Fatalf("responder expected (hasOutbound=false, done=true), got (%v, %v)", hasOutbound, done)
	}
}

func TestInteractiveAuthenticatorRoundTrip(t *testing.T) {
	initiator, responder := bindPair(t, "demo-secret")
	runHandshake(t, initiator, responder)

	if initiator.State() != AuthStateSucceeded {
		t.Fatalf("initiator state = %q", initiator.State())
	}
	if responder.State() != AuthStateSucceeded {
		t.Fatalf("responder state = %q", responder.State())
	}

	initKey, err := initiator.SessionKey()
	if err != nil {
		t.Fatalf("initiator SessionKey: %v", err)
	}
	respKey, err := responder.SessionKey()
	if err != nil {
		t.Fatalf("responder SessionKey: %v", err)
	}
	if !bytes.Equal(initKey, respKey) {
		t.Fatal("session keys differ")
	}
	if len(initKey) != 32 {
		t.Fatalf("unexpected session key length %d", len(initKey))
	}
}

func TestInteractiveAuthenticatorRejectsWrongPairingSecret(t *testing.T) {
	initiator := mustNewAuth(t, "demo-secret")
	responder := mustNewAuth(t, "other-secret")
	if err := initiator.Bind(initiatorMaterial()); err != nil {
		t.Fatalf("Bind(init): %v", err)
	}
	if err := responder.Bind(responderMaterial()); err != nil {
		t.Fatalf("Bind(resp): %v", err)
	}

	hello, err := initiator.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	accept, _, _, err := responder.Step(hello)
	if err != nil {
		t.Fatalf("responder Step(hello): %v", err)
	}

	_, _, _, err = initiator.Step(accept)
	if !errors.Is(err, ErrPeerAuthFailed) || !errors.Is(err, ErrAuthConfirmationMismatch) {
		t.Fatalf("expected confirmation mismatch, got %v", err)
	}
	if initiator.State() != AuthStateFailed {
		t.Fatalf("initiator state = %q", initiator.State())
	}
}

func TestInteractiveAuthenticatorRejectsTamperedShare(t *testing.T) {
	initiator, responder := bindPair(t, "demo-secret")

	hello, err := initiator.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	accept, _, _, err := responder.Step(hello)
	if err != nil {
		t.Fatalf("responder Step(hello): %v", err)
	}
	tampered, err := base64.RawURLEncoding.DecodeString(accept.Share)
	if err != nil {
		t.Fatalf("decode share: %v", err)
	}
	tampered[0] ^= 0x01
	accept.Share = base64.RawURLEncoding.EncodeToString(tampered)

	_, _, _, err = initiator.Step(accept)
	if err == nil {
		t.Fatal("expected tampered share to fail")
	}
	if initiator.State() != AuthStateFailed {
		t.Fatalf("initiator state = %q", initiator.State())
	}
}

func TestInteractiveAuthenticatorRejectsRoleConfusion(t *testing.T) {
	_, responder := bindPair(t, "demo-secret")

	// Craft a hello that swaps the roles.
	hello := Message{
		Scheme:        SchemeCPACEV2,
		Kind:          MessageKindHello,
		InitiatorRole: config.ModeExpose.String(),
		ResponderRole: config.ModeConnect.String(),
		Share:         base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
	}

	_, _, _, err := responder.Step(hello)
	if !errors.Is(err, ErrAuthRoleMismatch) {
		t.Fatalf("expected ErrAuthRoleMismatch, got %v", err)
	}
	if responder.State() != AuthStateFailed {
		t.Fatalf("responder state = %q", responder.State())
	}
}

func TestInteractiveAuthenticatorRejectsOutOfOrderMessage(t *testing.T) {
	_, responder := bindPair(t, "demo-secret")

	// Responder must see hello first; a bare confirm is out of order.
	confirm := Message{
		Scheme:       SchemeCPACEV2,
		Kind:         MessageKindConfirm,
		Confirmation: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x00}, 32)),
	}

	_, _, _, err := responder.Step(confirm)
	if !errors.Is(err, ErrAuthUnexpectedKind) {
		t.Fatalf("expected ErrAuthUnexpectedKind, got %v", err)
	}
	if responder.State() != AuthStateFailed {
		t.Fatalf("responder state = %q", responder.State())
	}
}

func TestInteractiveAuthenticatorRejectsSchemeMismatch(t *testing.T) {
	_, responder := bindPair(t, "demo-secret")

	hello := Message{
		Scheme:        "rtc2tcp-auth/bogus-v0",
		Kind:          MessageKindHello,
		InitiatorRole: config.ModeConnect.String(),
		ResponderRole: config.ModeExpose.String(),
		Share:         base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
	}

	_, _, _, err := responder.Step(hello)
	if !errors.Is(err, ErrAuthSchemeMismatch) {
		t.Fatalf("expected ErrAuthSchemeMismatch, got %v", err)
	}
	if responder.State() != AuthStateFailed {
		t.Fatalf("responder state = %q", responder.State())
	}
}

func TestInteractiveAuthenticatorRejectsSessionMismatch(t *testing.T) {
	initiator := mustNewAuth(t, "demo-secret")
	responder := mustNewAuth(t, "demo-secret")
	if err := initiator.Bind(initiatorMaterial()); err != nil {
		t.Fatalf("Bind(init): %v", err)
	}
	altMaterial := responderMaterial()
	altMaterial.SessionID = "session-2"
	if err := responder.Bind(altMaterial); err != nil {
		t.Fatalf("Bind(resp): %v", err)
	}

	hello, err := initiator.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	accept, _, _, err := responder.Step(hello)
	if err != nil {
		t.Fatalf("responder Step(hello): %v", err)
	}
	_, _, _, err = initiator.Step(accept)
	if !errors.Is(err, ErrPeerAuthFailed) {
		t.Fatalf("expected ErrPeerAuthFailed on session mismatch, got %v", err)
	}
}

func TestInteractiveAuthenticatorRejectsAllZeroShare(t *testing.T) {
	_, responder := bindPair(t, "demo-secret")

	hello := Message{
		Scheme:        SchemeCPACEV2,
		Kind:          MessageKindHello,
		InitiatorRole: config.ModeConnect.String(),
		ResponderRole: config.ModeExpose.String(),
		Share:         base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x00}, 32)),
	}

	_, _, _, err := responder.Step(hello)
	if !errors.Is(err, ErrAuthInvalidShare) {
		t.Fatalf("expected ErrAuthInvalidShare, got %v", err)
	}
}

func TestInteractiveAuthenticatorResponderCannotStart(t *testing.T) {
	responder := mustNewAuth(t, "demo-secret")
	if err := responder.Bind(responderMaterial()); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	_, err := responder.Start()
	if !errors.Is(err, ErrAuthStateOutOfOrder) {
		t.Fatalf("expected ErrAuthStateOutOfOrder, got %v", err)
	}
}

func TestInteractiveAuthenticatorDoubleStartFails(t *testing.T) {
	initiator := mustNewAuth(t, "demo-secret")
	if err := initiator.Bind(initiatorMaterial()); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, err := initiator.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := initiator.Start(); !errors.Is(err, ErrAuthStateOutOfOrder) {
		t.Fatalf("expected ErrAuthStateOutOfOrder on second Start, got %v", err)
	}
}

func TestInteractiveAuthenticatorRejectsInputAfterComplete(t *testing.T) {
	initiator, responder := bindPair(t, "demo-secret")
	runHandshake(t, initiator, responder)

	if _, _, _, err := responder.Step(Message{Scheme: SchemeTransitionalV2, Kind: MessageKindHello}); !errors.Is(err, ErrAuthStateOutOfOrder) {
		t.Fatalf("expected ErrAuthStateOutOfOrder, got %v", err)
	}
}

func TestInteractiveAuthenticatorTranscriptBindsFingerprints(t *testing.T) {
	initiator := mustNewAuth(t, "demo-secret")
	responder := mustNewAuth(t, "demo-secret")
	if err := initiator.Bind(initiatorMaterial()); err != nil {
		t.Fatalf("Bind(init): %v", err)
	}
	altMaterial := responderMaterial()
	altMaterial.LocalFingerprint = strings.ReplaceAll(altMaterial.LocalFingerprint, "CC", "EE")
	if err := responder.Bind(altMaterial); err != nil {
		t.Fatalf("Bind(resp): %v", err)
	}

	hello, err := initiator.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	accept, _, _, err := responder.Step(hello)
	if err != nil {
		t.Fatalf("responder Step(hello): %v", err)
	}
	_, _, _, err = initiator.Step(accept)
	if !errors.Is(err, ErrPeerAuthFailed) {
		t.Fatalf("expected ErrPeerAuthFailed on fingerprint mismatch, got %v", err)
	}
}

func TestInteractiveAuthenticatorRequiresBindBeforeStart(t *testing.T) {
	a := mustNewAuth(t, "demo-secret")
	if _, err := a.Start(); !errors.Is(err, ErrAuthUnbound) {
		t.Fatalf("expected ErrAuthUnbound, got %v", err)
	}
}

func TestDefaultSchemeIsCPACE(t *testing.T) {
	a := mustNewAuth(t, "demo-secret")
	if a.Name() != SchemeCPACEV2 {
		t.Fatalf("default scheme = %q, want %q", a.Name(), SchemeCPACEV2)
	}
}

func TestInteractiveAuthenticatorRoundTripAllSchemes(t *testing.T) {
	for _, scheme := range []string{SchemeCPACEV2, SchemeTransitionalV2} {
		t.Run(scheme, func(t *testing.T) {
			initiator, err := NewInteractiveAuthenticatorWithScheme("demo-secret", scheme)
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			responder, err := NewInteractiveAuthenticatorWithScheme("demo-secret", scheme)
			if err != nil {
				t.Fatalf("resp: %v", err)
			}
			if err := initiator.Bind(initiatorMaterial()); err != nil {
				t.Fatalf("Bind(init): %v", err)
			}
			if err := responder.Bind(responderMaterial()); err != nil {
				t.Fatalf("Bind(resp): %v", err)
			}
			runHandshake(t, initiator, responder)

			ik, _ := initiator.SessionKey()
			rk, _ := responder.SessionKey()
			if !bytes.Equal(ik, rk) {
				t.Fatal("session keys differ")
			}
		})
	}
}

func TestCPACEPeerRefusesTransitionalDowngrade(t *testing.T) {
	// A CPACE-configured responder must refuse a hello whose scheme is
	// the transitional ECDH scheme. The scheme-pin check fires before
	// any state mutation, taking the authenticator to FAILED.
	cpaceResponder, err := NewInteractiveAuthenticatorWithScheme("demo-secret", SchemeCPACEV2)
	if err != nil {
		t.Fatalf("NewInteractiveAuthenticatorWithScheme: %v", err)
	}
	if err := cpaceResponder.Bind(responderMaterial()); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	transitionalInitiator, err := NewInteractiveAuthenticatorWithScheme("demo-secret", SchemeTransitionalV2)
	if err != nil {
		t.Fatalf("NewInteractiveAuthenticatorWithScheme: %v", err)
	}
	if err := transitionalInitiator.Bind(initiatorMaterial()); err != nil {
		t.Fatalf("Bind(init): %v", err)
	}
	hello, err := transitionalInitiator.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	_, _, _, err = cpaceResponder.Step(hello)
	if !errors.Is(err, ErrAuthSchemeMismatch) {
		t.Fatalf("expected ErrAuthSchemeMismatch, got %v", err)
	}
	if cpaceResponder.State() != AuthStateFailed {
		t.Fatalf("cpaceResponder state = %q", cpaceResponder.State())
	}
}

func TestNewInteractiveAuthenticatorWithSchemeRejectsUnknown(t *testing.T) {
	if _, err := NewInteractiveAuthenticatorWithScheme("demo-secret", "bogus"); !errors.Is(err, ErrAuthUnsupportedScheme) {
		t.Fatalf("expected ErrAuthUnsupportedScheme, got %v", err)
	}
}

func TestInteractiveAuthenticatorCPACERejectsIdentityShare(t *testing.T) {
	// Identity element encoding is all-zero for Ristretto255; make sure
	// the responder catches it as an invalid share rather than crashing
	// through the group arithmetic.
	cpaceResponder, err := NewInteractiveAuthenticatorWithScheme("demo-secret", SchemeCPACEV2)
	if err != nil {
		t.Fatalf("NewInteractiveAuthenticatorWithScheme: %v", err)
	}
	if err := cpaceResponder.Bind(responderMaterial()); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	hello := Message{
		Scheme:        SchemeCPACEV2,
		Kind:          MessageKindHello,
		InitiatorRole: config.ModeConnect.String(),
		ResponderRole: config.ModeExpose.String(),
		Share:         base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x00}, 32)),
	}
	_, _, _, err = cpaceResponder.Step(hello)
	if !errors.Is(err, ErrAuthInvalidShare) {
		t.Fatalf("expected ErrAuthInvalidShare, got %v", err)
	}
}
