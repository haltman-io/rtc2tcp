package rendezvous

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/haltman-io/rtc2tcp/internal/signaling"
)

// dialRaw opens a raw WebSocket to a broker's /ws endpoint without
// going through the signaling client. Tests use this to observe
// broker-level behaviour (pings, deadlines) without also exercising
// the client-side keepalive.
func dialRaw(t *testing.T, wsURL string) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", wsURL, err)
	}
	return conn
}

// TestBrokerPingsPeersDuringIdle boots a real broker behind httptest
// and verifies it sends pings to idle peers. A reverse proxy
// (Cloudflare Tunnel, nginx, ALB) would otherwise idle-timeout the
// WebSocket while the peers are carrying traffic on the WebRTC
// DataChannel instead.
func TestBrokerPingsPeersDuringIdle(t *testing.T) {
	// Drive broker keepalives fast for the test. The broker package
	// declares these as vars for exactly this purpose.
	origPing, origPong := wsPingInterval, wsPongWait
	wsPingInterval = 50 * time.Millisecond
	wsPongWait = 2 * time.Second
	t.Cleanup(func() {
		wsPingInterval = origPing
		wsPongWait = origPong
	})

	broker := NewBroker(log.New(io.Discard, "", 0))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = broker.Shutdown(ctx)
	})

	server := httptest.NewServer(broker.Routes())
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	conn := dialRaw(t, wsURL)
	defer conn.Close()

	// Register as an expose peer so the broker treats this as a
	// long-lived waiter rather than rejecting the first read.
	if err := conn.WriteJSON(signaling.Message{
		Type: signaling.MessageTypeRegister,
		Register: &signaling.Register{
			RendezvousToken: "keepalive-test",
			Mode:            "expose",
		},
	}); err != nil {
		t.Fatalf("write register: %v", err)
	}

	// Consume the registered ack so the read buffer doesn't fill.
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read register ack: %v", err)
	}

	var pingCount int32
	conn.SetPingHandler(func(appData string) error {
		atomic.AddInt32(&pingCount, 1)
		return conn.WriteControl(
			websocket.PongMessage,
			[]byte(appData),
			time.Now().Add(time.Second),
		)
	})

	// Gorilla panics on a second read after any error, so we can't
	// poll — instead, a single long-lived ReadMessage blocks while
	// processing control frames via the ping handler. The main
	// goroutine polls pingCount and closes the conn to unblock the
	// reader when done.
	readExited := make(chan struct{})
	go func() {
		defer close(readExited)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&pingCount) >= 3 {
			_ = conn.Close()
			<-readExited
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = conn.Close()
	<-readExited
	t.Fatalf("expected ≥3 broker→peer pings within 1.5s @ 50ms interval, got %d", atomic.LoadInt32(&pingCount))
}

// TestBrokerRepliesToAppLevelPing confirms the broker understands
// the application-layer ping/pong JSON messages. This is the primary
// keepalive path for deployments behind intermediaries (Cloudflare
// Tunnel, AWS ALB, nginx) that don't honour WebSocket control frames.
func TestBrokerRepliesToAppLevelPing(t *testing.T) {
	broker := NewBroker(log.New(io.Discard, "", 0))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = broker.Shutdown(ctx)
	})

	server := httptest.NewServer(broker.Routes())
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn := dialRaw(t, wsURL)
	defer conn.Close()

	if err := conn.WriteJSON(signaling.Message{
		Type: signaling.MessageTypeRegister,
		Register: &signaling.Register{
			RendezvousToken: "ping-test",
			Mode:            "expose",
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Consume the register ack.
	var ack signaling.Message
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read ack: %v", err)
	}

	// Send an app-level ping with a distinctive token and expect a
	// pong back with the same token.
	if err := conn.WriteJSON(signaling.Message{
		Type: signaling.MessageTypePing,
		Ping: &signaling.Ping{Token: "probe-42"},
	}); err != nil {
		t.Fatalf("send ping: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var pong signaling.Message
	if err := conn.ReadJSON(&pong); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if pong.Type != signaling.MessageTypePong {
		t.Fatalf("expected %q, got %q", signaling.MessageTypePong, pong.Type)
	}
	if pong.Pong == nil || pong.Pong.Token != "probe-42" {
		t.Fatalf("expected pong with echoed token %q, got %+v", "probe-42", pong.Pong)
	}
}

// TestBrokerEvictsSilentPeer confirms the read deadline fires when a
// peer stops responding to pings entirely (e.g. blackholed path). The
// broker should cut the connection rather than leaking goroutines.
func TestBrokerEvictsSilentPeer(t *testing.T) {
	origPing, origPong := wsPingInterval, wsPongWait
	wsPingInterval = 50 * time.Millisecond
	wsPongWait = 200 * time.Millisecond
	t.Cleanup(func() {
		wsPingInterval = origPing
		wsPongWait = origPong
	})

	broker := NewBroker(log.New(io.Discard, "", 0))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = broker.Shutdown(ctx)
	})

	server := httptest.NewServer(broker.Routes())
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn := dialRaw(t, wsURL)
	defer conn.Close()

	if err := conn.WriteJSON(map[string]any{
		"type": "register",
		"register": map[string]any{
			"mode":             "expose",
			"rendezvous_token": "silent-peer",
		},
	}); err != nil {
		t.Fatalf("write register: %v", err)
	}
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read register ack: %v", err)
	}

	// Swallow pings WITHOUT responding with pongs — simulates a dead
	// intermediary that keeps TCP alive but drops control frames.
	conn.SetPingHandler(func(string) error { return nil })

	// The broker's pongWait is 200ms. Read should error out within
	// a small multiple of that once the broker's read deadline
	// expires and it closes the conn.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Fatal("expected read error after broker evicted silent peer; got nil")
	}
}
