package webrtc

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"testing"

	"github.com/haltman-io/rtc2tcp/internal/auth"
	"github.com/haltman-io/rtc2tcp/internal/config"
)

func TestExtractTransportFingerprint(t *testing.T) {
	sdp := "v=0\r\n" +
		"o=- 0 0 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"a=fingerprint:sha-256 12:34:56:78\r\n"

	fingerprint, err := ExtractTransportFingerprint(sdp)
	if err != nil {
		t.Fatalf("ExtractTransportFingerprint: %v", err)
	}

	if fingerprint != "SHA-256 12:34:56:78" {
		t.Fatalf("unexpected fingerprint %q", fingerprint)
	}
}

func TestExtractTransportFingerprintMissing(t *testing.T) {
	if _, err := ExtractTransportFingerprint("v=0\r\n"); err == nil {
		t.Fatal("expected ExtractTransportFingerprint to fail when fingerprint is missing")
	}
}

func TestExtractTransportFingerprintPrefersApplicationMedia(t *testing.T) {
	sdp := "v=0\r\n" +
		"o=- 0 0 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=fingerprint:sha-256 11:11:11:11\r\n" +
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" +
		"a=fingerprint:sha-256 22:22:22:22\r\n" +
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"a=fingerprint:sha-256 33:33:33:33\r\n"

	fingerprint, err := ExtractTransportFingerprint(sdp)
	if err != nil {
		t.Fatalf("ExtractTransportFingerprint: %v", err)
	}
	if fingerprint != "SHA-256 33:33:33:33" {
		t.Fatalf("unexpected fingerprint %q", fingerprint)
	}
}

func TestPrepareInboundPayloadChannelBeforeAuthFails(t *testing.T) {
	session := &Session{
		stateMachine: newStateMachineForTest(t, StateAuthPending),
		authReady:    make(chan struct{}),
	}

	err := session.prepareInboundPayloadChannel()
	if !errors.Is(err, ErrPreAuthPayloadChannel) {
		t.Fatalf("expected ErrPreAuthPayloadChannel, got %v", err)
	}
}

func TestHandleControlMessageRejectsMessagesAfterAuthenticated(t *testing.T) {
	session := &Session{
		logger:       log.New(io.Discard, "", 0),
		stateMachine: newStateMachineForTest(t, StateAuthenticated),
		authReady:    make(chan struct{}),
	}

	payload, err := json.Marshal(auth.Message{
		Scheme: auth.SchemeTransitionalV2,
		Kind:   auth.MessageKindHello,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if err := session.handleControlMessage(payload); !errors.Is(err, ErrUnexpectedAuthControlReplay) {
		t.Fatalf("expected ErrUnexpectedAuthControlReplay, got %v", err)
	}
}

func TestHandleControlMessageRejectsUnknownFields(t *testing.T) {
	authenticator, err := auth.NewInteractiveAuthenticator("demo-secret")
	if err != nil {
		t.Fatalf("NewInteractiveAuthenticator: %v", err)
	}

	session := &Session{
		logger:            log.New(io.Discard, "", 0),
		mode:              config.ModeExpose,
		sessionID:         "session-1",
		authenticator:     authenticator,
		stateMachine:      newStateMachineForTest(t, StateAuthPending),
		localFingerprint:  "SHA-256 CC:DD",
		remoteFingerprint: "SHA-256 AA:BB",
		authReady:         make(chan struct{}),
	}

	// A message with an unknown field must be rejected before any
	// authenticator state mutation.
	err = session.handleControlMessage([]byte(`{"scheme":"rtc2tcp-auth/interactive-ecdh-v2a","kind":"hello","extra":"nope"}`))
	if err == nil {
		t.Fatal("expected rejection of unknown field")
	}
}

func newStateMachineForTest(t *testing.T, target SessionState) *StateMachine {
	t.Helper()

	stateMachine := NewStateMachine()
	for _, state := range []SessionState{
		StateRendezvous,
		StateSignaling,
		StateAuthPending,
		StateAuthenticated,
		StateStreaming,
		StateClosing,
		StateClosed,
	} {
		if stateMachine.State() == target {
			return stateMachine
		}
		if err := stateMachine.Transition(state); err != nil {
			t.Fatalf("Transition(%s): %v", state, err)
		}
		if state == target {
			return stateMachine
		}
	}

	t.Fatalf("target state %s not reached", target)
	return nil
}
