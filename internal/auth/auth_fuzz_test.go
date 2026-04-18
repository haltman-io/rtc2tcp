package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/haltman-io/rtc2tcp/internal/config"
)

// FuzzStep exercises InteractiveAuthenticator.Step with arbitrary JSON
// inputs. The invariants asserted on every run:
//
//   - Step must never panic.
//   - If Step returns a non-nil error, the authenticator must transition
//     to AuthStateFailed.
//   - AuthStateFailed must be terminal: any further Step invocation on a
//     FAILED authenticator must return a non-nil error without entering a
//     non-FAILED state.
//   - If Step reports done=true, State must be AuthStateSucceeded and
//     SessionKey must return a non-empty 32-byte key.
//   - The authenticator's internal state must remain a known enum value.
func FuzzStep(f *testing.F) {
	// Seed with the three valid wire frames that a real handshake
	// produces so the fuzzer starts with live bytes rather than a cold
	// corpus.
	initiator, err := NewInteractiveAuthenticator("fuzz-secret")
	if err != nil {
		f.Fatalf("seed initiator: %v", err)
	}
	if err := initiator.Bind(initiatorMaterial()); err != nil {
		f.Fatalf("seed initiator bind: %v", err)
	}
	responder, err := NewInteractiveAuthenticator("fuzz-secret")
	if err != nil {
		f.Fatalf("seed responder: %v", err)
	}
	if err := responder.Bind(responderMaterial()); err != nil {
		f.Fatalf("seed responder bind: %v", err)
	}

	hello, err := initiator.Start()
	if err != nil {
		f.Fatalf("seed Start: %v", err)
	}
	helloBytes, err := json.Marshal(hello)
	if err != nil {
		f.Fatalf("marshal hello: %v", err)
	}
	accept, _, _, err := responder.Step(hello)
	if err != nil {
		f.Fatalf("seed responder Step(hello): %v", err)
	}
	acceptBytes, err := json.Marshal(accept)
	if err != nil {
		f.Fatalf("marshal accept: %v", err)
	}
	confirm, _, _, err := initiator.Step(accept)
	if err != nil {
		f.Fatalf("seed initiator Step(accept): %v", err)
	}
	confirmBytes, err := json.Marshal(confirm)
	if err != nil {
		f.Fatalf("marshal confirm: %v", err)
	}

	for _, seed := range [][]byte{
		helloBytes,
		acceptBytes,
		confirmBytes,
		[]byte(`{}`),
		[]byte(`{"scheme":"` + SchemeCPACEV2 + `","kind":"hello"}`),
		[]byte(`{"scheme":"` + SchemeCPACEV2 + `","kind":"nope"}`),
		[]byte(`{"scheme":"wrong","kind":"hello"}`),
		[]byte(`not json`),
		[]byte(``),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var msg Message
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&msg); err != nil {
			// Malformed JSON is not interesting at the Step layer; that
			// is the session's decoder's problem. Ignore.
			return
		}

		assertStateInvariants := func(state AuthState) {
			switch state {
			case AuthStateInit,
				AuthStateSentHello,
				AuthStateSentAccept,
				AuthStateSentConfirm,
				AuthStateSucceeded,
				AuthStateFailed:
			default:
				t.Fatalf("invalid state %q", state)
			}
		}

		for _, role := range []config.PeerMode{config.ModeConnect, config.ModeExpose} {
			a, err := NewInteractiveAuthenticator("fuzz-secret")
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			material := initiatorMaterial()
			if role == config.ModeExpose {
				material = responderMaterial()
			}
			if err := a.Bind(material); err != nil {
				t.Fatalf("bind: %v", err)
			}

			_, hasOutbound, done, stepErr := a.Step(msg)
			state := a.State()
			assertStateInvariants(state)

			if stepErr != nil {
				if state != AuthStateFailed {
					t.Fatalf("Step returned error but state is %q, want FAILED: err=%v", state, stepErr)
				}
				if hasOutbound {
					t.Fatalf("Step returned error alongside outbound message (should be empty): err=%v", stepErr)
				}
				if done {
					t.Fatalf("Step returned error alongside done=true: err=%v", stepErr)
				}
			}

			if done {
				if state != AuthStateSucceeded {
					t.Fatalf("Step reported done=true but state is %q, want SUCCEEDED", state)
				}
				key, err := a.SessionKey()
				if err != nil {
					t.Fatalf("SessionKey after done=true: %v", err)
				}
				if len(key) != 32 {
					t.Fatalf("SessionKey length after done=true: %d", len(key))
				}
			} else if state == AuthStateSucceeded {
				t.Fatalf("state is SUCCEEDED but Step reported done=false")
			}

			if state == AuthStateFailed {
				_, _, _, againErr := a.Step(msg)
				if againErr == nil {
					t.Fatal("FAILED is not terminal: second Step accepted input without error")
				}
				if !errors.Is(againErr, ErrAuthStateOutOfOrder) {
					// Any non-nil error is acceptable, but the canonical
					// error for post-FAILED inputs is ErrAuthStateOutOfOrder.
					// We do not fail here on a different error value as long
					// as one is returned.
					_ = againErr
				}
				if after := a.State(); after != AuthStateFailed {
					t.Fatalf("state changed away from FAILED: %q", after)
				}
			}
		}
	})
}
