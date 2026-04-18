package webrtc

import (
	"fmt"
	"sync"
)

type SessionState string

const (
	StateInit          SessionState = "INIT"
	StateRendezvous    SessionState = "RENDEZVOUS"
	StateSignaling     SessionState = "SIGNALING"
	StateAuthPending   SessionState = "AUTH_PENDING"
	StateAuthenticated SessionState = "AUTHENTICATED"
	StateStreaming     SessionState = "STREAMING"
	StateClosing       SessionState = "CLOSING"
	StateClosed        SessionState = "CLOSED"
	StateFailed        SessionState = "FAILED"
)

var allowedTransitions = map[SessionState]map[SessionState]struct{}{
	StateInit: {
		StateRendezvous: {},
		StateClosing:    {},
		StateFailed:     {},
	},
	StateRendezvous: {
		StateSignaling: {},
		StateClosing:   {},
		StateFailed:    {},
	},
	StateSignaling: {
		StateAuthPending: {},
		StateClosing:     {},
		StateFailed:      {},
	},
	StateAuthPending: {
		StateAuthenticated: {},
		StateClosing:       {},
		StateFailed:        {},
	},
	StateAuthenticated: {
		StateStreaming: {},
		StateClosing:   {},
		StateFailed:    {},
	},
	StateStreaming: {
		StateStreaming: {},
		StateClosing:   {},
		StateFailed:    {},
	},
	StateClosing: {
		StateClosed: {},
		StateFailed: {},
	},
}

type StateMachine struct {
	mu    sync.Mutex
	state SessionState
}

func NewStateMachine() *StateMachine {
	return &StateMachine{state: StateInit}
}

func (m *StateMachine) State() SessionState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *StateMachine) Transition(next SessionState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == next && next == StateStreaming {
		return nil
	}

	allowed := allowedTransitions[m.state]
	if _, ok := allowed[next]; !ok {
		return fmt.Errorf("invalid session state transition %s -> %s", m.state, next)
	}

	m.state = next
	return nil
}

func (m *StateMachine) IsOneOf(states ...SessionState) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, state := range states {
		if m.state == state {
			return true
		}
	}
	return false
}
