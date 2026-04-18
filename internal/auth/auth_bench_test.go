package auth

import (
	"encoding/json"
	"testing"
)

// BenchmarkInteractiveHandshakeCPACE measures a complete three-frame
// CPACE-Ristretto255 handshake end-to-end including Bind, scalar draw,
// generator derivation, transcript, HKDF, HMAC, and key confirmation on
// both peers. It does not include WebRTC signalling or DataChannel
// round-trip latency.
func BenchmarkInteractiveHandshakeCPACE(b *testing.B) {
	for i := 0; i < b.N; i++ {
		initiator, err := NewInteractiveAuthenticatorWithScheme("bench-secret", SchemeCPACEV2)
		if err != nil {
			b.Fatalf("init: %v", err)
		}
		responder, err := NewInteractiveAuthenticatorWithScheme("bench-secret", SchemeCPACEV2)
		if err != nil {
			b.Fatalf("resp: %v", err)
		}
		if err := initiator.Bind(initiatorMaterial()); err != nil {
			b.Fatalf("bind init: %v", err)
		}
		if err := responder.Bind(responderMaterial()); err != nil {
			b.Fatalf("bind resp: %v", err)
		}

		hello, err := initiator.Start()
		if err != nil {
			b.Fatalf("start: %v", err)
		}
		accept, _, _, err := responder.Step(hello)
		if err != nil {
			b.Fatalf("resp step hello: %v", err)
		}
		confirm, _, _, err := initiator.Step(accept)
		if err != nil {
			b.Fatalf("init step accept: %v", err)
		}
		if _, _, _, err := responder.Step(confirm); err != nil {
			b.Fatalf("resp step confirm: %v", err)
		}
	}
}

// BenchmarkInteractiveHandshakeTransitional measures the same flow
// under the transitional ECDH scheme. Useful as a baseline for the
// CPACE overhead.
func BenchmarkInteractiveHandshakeTransitional(b *testing.B) {
	for i := 0; i < b.N; i++ {
		initiator, err := NewInteractiveAuthenticatorWithScheme("bench-secret", SchemeTransitionalV2)
		if err != nil {
			b.Fatalf("init: %v", err)
		}
		responder, err := NewInteractiveAuthenticatorWithScheme("bench-secret", SchemeTransitionalV2)
		if err != nil {
			b.Fatalf("resp: %v", err)
		}
		if err := initiator.Bind(initiatorMaterial()); err != nil {
			b.Fatalf("bind init: %v", err)
		}
		if err := responder.Bind(responderMaterial()); err != nil {
			b.Fatalf("bind resp: %v", err)
		}

		hello, err := initiator.Start()
		if err != nil {
			b.Fatalf("start: %v", err)
		}
		accept, _, _, err := responder.Step(hello)
		if err != nil {
			b.Fatalf("resp step hello: %v", err)
		}
		confirm, _, _, err := initiator.Step(accept)
		if err != nil {
			b.Fatalf("init step accept: %v", err)
		}
		if _, _, _, err := responder.Step(confirm); err != nil {
			b.Fatalf("resp step confirm: %v", err)
		}
	}
}

// BenchmarkMarshalHello measures Message JSON marshaling on the hot
// path (each auth frame is serialised once per handshake). Catches
// regressions in Message shape that affect the wire path.
func BenchmarkMarshalHello(b *testing.B) {
	initiator, err := NewInteractiveAuthenticator("bench-secret")
	if err != nil {
		b.Fatalf("init: %v", err)
	}
	if err := initiator.Bind(initiatorMaterial()); err != nil {
		b.Fatalf("bind: %v", err)
	}
	hello, err := initiator.Start()
	if err != nil {
		b.Fatalf("start: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(hello); err != nil {
			b.Fatalf("marshal: %v", err)
		}
	}
}

// BenchmarkBuildTranscript isolates the transcript construction cost.
// Transcript is rebuilt once per handshake per peer; this benchmark
// exists so a regression in `writeLenPrefixed` or the SHA-256 chain
// shows up with a stable number.
func BenchmarkBuildTranscript(b *testing.B) {
	initiatorShare := make([]byte, 32)
	responderShare := make([]byte, 32)
	for i := range initiatorShare {
		initiatorShare[i] = byte(i)
		responderShare[i] = byte(255 - i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildTranscript(
			SchemeCPACEV2,
			"bench-session",
			"connect",
			"expose",
			"SHA-256 AA:BB",
			"SHA-256 CC:DD",
			initiatorShare,
			responderShare,
		)
	}
}
