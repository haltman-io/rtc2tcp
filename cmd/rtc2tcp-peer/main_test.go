package main

import (
	"context"
	"errors"
	"testing"

	"github.com/haltman-io/rtc2tcp/internal/auth"
	rtcwebrtc "github.com/haltman-io/rtc2tcp/internal/webrtc"
)

func TestClassifyPreAuthFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		err          error
		wantEvent    string
		wantMessage  string
		wantReason   string
		reasonSource func(error) string
	}{
		{
			name:         "auth scheme mismatch",
			err:          auth.ErrAuthSchemeMismatch,
			wantEvent:    "auth_failure",
			wantMessage:  "authentication failed",
			wantReason:   "scheme_mismatch",
			reasonSource: authFailureReason,
		},
		{
			name:         "auth timeout",
			err:          context.DeadlineExceeded,
			wantEvent:    "auth_failure",
			wantMessage:  "authentication failed",
			wantReason:   "timeout",
			reasonSource: authFailureReason,
		},
		{
			name:         "peer connection failed",
			err:          rtcwebrtc.ErrPeerConnectionFailed,
			wantEvent:    "transport_failure",
			wantMessage:  "transport failed before authentication",
			wantReason:   "peer_connection_failed",
			reasonSource: transportFailureReason,
		},
		{
			name:         "wrapped peer connection closed",
			err:          errors.Join(errors.New("wrapper"), rtcwebrtc.ErrPeerConnectionClosed),
			wantEvent:    "transport_failure",
			wantMessage:  "transport failed before authentication",
			wantReason:   "peer_connection_closed",
			reasonSource: transportFailureReason,
		},
		{
			name:         "generic pre-auth failure stays auth-shaped",
			err:          errors.New("unknown failure"),
			wantEvent:    "auth_failure",
			wantMessage:  "authentication failed",
			wantReason:   "unclassified",
			reasonSource: authFailureReason,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := classifyPreAuthFailure(tt.err)
			if got.event != tt.wantEvent {
				t.Fatalf("event = %q, want %q", got.event, tt.wantEvent)
			}
			if got.message != tt.wantMessage {
				t.Fatalf("message = %q, want %q", got.message, tt.wantMessage)
			}

			if reason := tt.reasonSource(tt.err); reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}
