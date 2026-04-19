package signaling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// withFastKeepalive overrides the package keepalive tunables for the
// duration of a test and restores them after. Tests run sequentially
// per package, so racing on these vars is not a concern.
func withFastKeepalive(t *testing.T, interval, pong time.Duration) {
	t.Helper()
	origPing, origPong, origAppPing := wsPingInterval, wsPongWait, appPingInterval
	wsPingInterval = interval
	wsPongWait = pong
	appPingInterval = interval
	t.Cleanup(func() {
		wsPingInterval = origPing
		wsPongWait = origPong
		appPingInterval = origAppPing
	})
}

func wsURLFromHTTP(server *httptest.Server) string {
	return "ws" + strings.TrimPrefix(server.URL, "http") + "/"
}

// TestClientSendsPings verifies the keepalive goroutine actually
// writes ping frames to the wire. This is the test that would have
// caught the original bug.
func TestClientSendsPings(t *testing.T) {
	withFastKeepalive(t, 50*time.Millisecond, 2*time.Second)

	var pingCount int32
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("server upgrade: %v", err)
			return
		}
		defer conn.Close()

		conn.SetPingHandler(func(appData string) error {
			atomic.AddInt32(&pingCount, 1)
			return conn.WriteControl(
				websocket.PongMessage,
				[]byte(appData),
				time.Now().Add(time.Second),
			)
		})

		// Drain frames; ping handler fires inside NextReader().
		for {
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := Dial(ctx, wsURLFromHTTP(server))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Expect ≥3 pings in 300ms at a 50ms interval.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&pingCount) >= 3 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected at least 3 pings from client, got %d", atomic.LoadInt32(&pingCount))
}

// TestClientSurvivesIdleBeyondNaiveTimeout proves the connection
// survives an idle window that would have killed the pre-fix code
// (the server here simulates a proxy by doing nothing at the app
// layer). With keepalive working, the client's ticker keeps the WS
// alive and the pong handler refreshes read deadlines.
func TestClientSurvivesIdleBeyondNaiveTimeout(t *testing.T) {
	withFastKeepalive(t, 50*time.Millisecond, 500*time.Millisecond)

	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("server upgrade: %v", err)
			return
		}
		defer conn.Close()
		// Default ping handler on the server auto-responds with pong.
		for {
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := Dial(ctx, wsURLFromHTTP(server))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Idle for 4 × pongWait. Without pings the read would have
	// blown up after 500ms; with pings, nothing fires.
	select {
	case <-time.After(2 * time.Second):
	case msg, ok := <-client.Events():
		if !ok {
			t.Fatal("client events channel closed during idle")
		}
		if msg.Type == MessageTypeError {
			t.Fatalf("client surfaced error during idle: %+v", msg.Error)
		}
	}
}

// TestClientSendsApplicationPings confirms the JSON-level keepalive
// is actually writing application frames to the wire — the
// bulletproof layer needed for intermediaries (cloudflared over QUIC)
// that ignore WebSocket control frames for idle accounting.
func TestClientSendsApplicationPings(t *testing.T) {
	withFastKeepalive(t, 50*time.Millisecond, 2*time.Second)

	var appPingCount int32
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("server upgrade: %v", err)
			return
		}
		defer conn.Close()

		// Read app frames; every ping message increments the counter
		// and is answered with a pong so the client doesn't trip its
		// own read deadline.
		for {
			var msg Message
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Type == MessageTypePing {
				atomic.AddInt32(&appPingCount, 1)
				token := ""
				if msg.Ping != nil {
					token = msg.Ping.Token
				}
				if err := conn.WriteJSON(Message{
					Type: MessageTypePong,
					Pong: &Pong{Token: token},
				}); err != nil {
					return
				}
			}
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := Dial(ctx, wsURLFromHTTP(server))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Wait up to 1s for ≥3 app-level pings at 50ms interval.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&appPingCount) >= 3 {
			// The client's read loop MUST swallow pongs — peer code
			// should never see them on the events channel.
			select {
			case msg := <-client.Events():
				t.Fatalf("pong leaked to events channel: %+v", msg)
			case <-time.After(100 * time.Millisecond):
				// No events — correct.
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected ≥3 application-level pings within 1s, got %d", atomic.LoadInt32(&appPingCount))
}

// TestClientRepliesToBrokerInitiatedPings — the symmetric case:
// broker (or a future rtc2tcp mesh node) sends an app-level ping
// and the client replies with a pong, without the peer event loop
// seeing either.
func TestClientRepliesToBrokerInitiatedPings(t *testing.T) {
	withFastKeepalive(t, 10*time.Second, 2*time.Second)

	var pongCount int32
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("server upgrade: %v", err)
			return
		}
		defer conn.Close()

		// Push a ping immediately, then another.
		for i := 0; i < 3; i++ {
			if err := conn.WriteJSON(Message{
				Type: MessageTypePing,
				Ping: &Ping{Token: "srv"},
			}); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}

		// Count pongs arriving back.
		for {
			var msg Message
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Type == MessageTypePong {
				atomic.AddInt32(&pongCount, 1)
			}
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := Dial(ctx, wsURLFromHTTP(server))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&pongCount) >= 3 {
			// Pings from the broker must also be swallowed locally.
			select {
			case msg := <-client.Events():
				t.Fatalf("ping leaked to events channel: %+v", msg)
			case <-time.After(50 * time.Millisecond):
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected client to reply with ≥3 pongs, got %d", atomic.LoadInt32(&pongCount))
}

// TestClientSurfacesReadErrorOnDeadServer confirms the failure path
// still works: if the server dies without a close frame, the client
// emits a broker-read error so the caller can react.
func TestClientSurfacesReadErrorOnDeadServer(t *testing.T) {
	withFastKeepalive(t, 50*time.Millisecond, 200*time.Millisecond)

	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	connReady := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("server upgrade: %v", err)
			return
		}
		connReady <- conn
		// Hold the handler open long enough for the test to close
		// the underlying TCP from behind the client.
		time.Sleep(time.Second)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := Dial(ctx, wsURLFromHTTP(server))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Slam the server-side conn shut without a close frame to
	// simulate a proxy dropping the connection.
	serverConn := <-connReady
	_ = serverConn.UnderlyingConn().Close()

	select {
	case msg, ok := <-client.Events():
		if !ok {
			// events channel closed is also an acceptable signal of
			// broker loss; the main.go event loop treats both as
			// broker detachment post-auth.
			return
		}
		if msg.Type != MessageTypeError || msg.Error == nil || msg.Error.Code != "broker-read" {
			t.Fatalf("expected broker-read error, got %+v", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not surface broker-read error within 1s of server shutdown")
	}
}
