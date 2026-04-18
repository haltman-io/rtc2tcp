package webrtc

import "testing"

func TestStateMachineRejectsInvalidTransition(t *testing.T) {
	stateMachine := NewStateMachine()

	if err := stateMachine.Transition(StateStreaming); err == nil {
		t.Fatal("expected invalid transition INIT -> STREAMING to fail")
	}
}

func TestStateMachineAllowsStreamingSelfTransition(t *testing.T) {
	stateMachine := NewStateMachine()
	for _, state := range []SessionState{
		StateRendezvous,
		StateSignaling,
		StateAuthPending,
		StateAuthenticated,
		StateStreaming,
	} {
		if err := stateMachine.Transition(state); err != nil {
			t.Fatalf("Transition(%s): %v", state, err)
		}
	}

	if err := stateMachine.Transition(StateStreaming); err != nil {
		t.Fatalf("expected STREAMING -> STREAMING to succeed, got %v", err)
	}
}
