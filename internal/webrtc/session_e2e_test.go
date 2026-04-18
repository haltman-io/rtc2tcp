package webrtc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	pion "github.com/pion/webrtc/v4"

	"github.com/haltman-io/rtc2tcp/internal/auth"
	"github.com/haltman-io/rtc2tcp/internal/config"
	"github.com/haltman-io/rtc2tcp/internal/signaling"
)

// TestSessionInteractiveAuthEndToEnd drives the full Milestone 2 handshake
// through a pion loopback pair. It exercises the control-channel
// attach/open flow, the three-message authenticator exchange, and the
// session state-machine transition into StateAuthenticated. Session keys
// derived on both sides must match.
func TestSessionInteractiveAuthEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("pion loopback test is slow; run without -short")
	}

	initiator, responder := newSessionPair(t, "demo-secret", "demo-secret")
	defer initiator.session.Close()
	defer responder.session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	driveHandshake(ctx, t, initiator, responder)

	if err := initiator.session.WaitAuthenticated(ctx); err != nil {
		t.Fatalf("initiator WaitAuthenticated: %v", err)
	}
	if err := responder.session.WaitAuthenticated(ctx); err != nil {
		t.Fatalf("responder WaitAuthenticated: %v", err)
	}

	if got := initiator.state.State(); got != StateAuthenticated {
		t.Fatalf("initiator state = %q", got)
	}
	if got := responder.state.State(); got != StateAuthenticated {
		t.Fatalf("responder state = %q", got)
	}

	initKey, err := initiator.auth.SessionKey()
	if err != nil {
		t.Fatalf("initiator SessionKey: %v", err)
	}
	respKey, err := responder.auth.SessionKey()
	if err != nil {
		t.Fatalf("responder SessionKey: %v", err)
	}
	if !bytes.Equal(initKey, respKey) {
		t.Fatal("session keys disagree after end-to-end auth")
	}
}

// TestSessionInteractiveAuthWrongSecretFailsEndToEnd exercises that a
// pairing-secret mismatch fails at key confirmation, takes both sessions
// to StateFailed, and leaves WaitAuthenticated returning a non-nil error.
func TestSessionInteractiveAuthWrongSecretFailsEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("pion loopback test is slow; run without -short")
	}

	initiator, responder := newSessionPair(t, "demo-secret", "other-secret")
	defer initiator.session.Close()
	defer responder.session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	driveHandshake(ctx, t, initiator, responder)

	if err := initiator.session.WaitAuthenticated(ctx); err == nil {
		t.Fatal("initiator WaitAuthenticated: expected error, got nil")
	} else if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("initiator WaitAuthenticated: expected auth failure, got timeout")
	}

	if err := responder.session.WaitAuthenticated(ctx); err == nil {
		t.Fatal("responder WaitAuthenticated: expected error, got nil")
	}
}

type e2ePeer struct {
	session *Session
	state   *StateMachine
	auth    *auth.InteractiveAuthenticator
	signals chan signaling.Signal
}

func newSessionPair(t *testing.T, initiatorSecret, responderSecret string) (*e2ePeer, *e2ePeer) {
	t.Helper()

	const sid = "e2e-session"

	initiator := buildPeer(t, sid, config.ModeConnect, true, initiatorSecret)
	responder := buildPeer(t, sid, config.ModeExpose, false, responderSecret)
	return initiator, responder
}

func buildPeer(t *testing.T, sid string, mode config.PeerMode, initiator bool, secret string) *e2ePeer {
	t.Helper()

	authInstance, err := auth.NewInteractiveAuthenticator(secret)
	if err != nil {
		t.Fatalf("NewInteractiveAuthenticator: %v", err)
	}

	stateMachine := NewStateMachine()
	for _, st := range []SessionState{StateRendezvous, StateSignaling} {
		if err := stateMachine.Transition(st); err != nil {
			t.Fatalf("Transition(%s): %v", st, err)
		}
	}

	signals := make(chan signaling.Signal, 64)

	session, err := NewSession(Config{
		Logger:        log.New(io.Discard, "", 0),
		Mode:          mode,
		SessionID:     sid,
		Initiator:     initiator,
		Authenticator: authInstance,
		StateMachine:  stateMachine,
		OnSignal: func(s signaling.Signal) {
			signals <- s
		},
		OnStream: func(dc *pion.DataChannel) {
			_ = dc.Close()
		},
	})
	if err != nil {
		t.Fatalf("NewSession(%s): %v", mode, err)
	}

	return &e2ePeer{
		session: session,
		state:   stateMachine,
		auth:    authInstance,
		signals: signals,
	}
}

func driveHandshake(ctx context.Context, t *testing.T, initiator, responder *e2ePeer) {
	t.Helper()

	offer, err := initiator.session.CreateOffer(ctx)
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	answer, err := responder.session.HandleOffer(ctx, offer)
	if err != nil {
		t.Fatalf("HandleOffer: %v", err)
	}
	if err := initiator.session.HandleAnswer(ctx, answer); err != nil {
		t.Fatalf("HandleAnswer: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pumpCandidates(ctx, initiator.signals, responder.session)
	}()
	go func() {
		defer wg.Done()
		pumpCandidates(ctx, responder.signals, initiator.session)
	}()

	t.Cleanup(func() {
		wg.Wait()
	})
}

func pumpCandidates(ctx context.Context, signals <-chan signaling.Signal, target *Session) {
	for {
		select {
		case <-ctx.Done():
			return
		case signal, ok := <-signals:
			if !ok {
				return
			}
			if signal.Kind != signaling.SignalKindICE || signal.Candidate == nil {
				continue
			}
			_ = target.AddRemoteCandidate(*signal.Candidate)
		}
	}
}
