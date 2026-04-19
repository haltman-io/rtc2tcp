package signaling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const maxBrokerMessageBytes = 1 << 20

// Keepalive tunables. Declared as vars (not consts) so tests can drive
// real time fast without refactoring the API. Production code should
// not mutate these after Dial.
//
// Two layers:
//
//  1. WebSocket ping/pong frames (wsPingInterval / wsPongWait).
//     Standards-compliant, cheap. Broker's default gorilla handler
//     auto-pongs. Counts as liveness on most intermediaries.
//
//  2. Application-level ping/pong JSON messages (appPingInterval).
//     Generates real DATA frames on the wire, not control frames.
//     Required for intermediaries that treat WS control frames
//     inconsistently — notably cloudflared (Cloudflare Tunnel) over
//     QUIC, where ping frames have been observed to not reset the
//     idle timer. App-level frames always count.
var (
	wsPingInterval  = 20 * time.Second
	wsPongWait      = 60 * time.Second
	wsWriteWait     = 10 * time.Second
	appPingInterval = 15 * time.Second
)

type Client struct {
	conn   *websocket.Conn
	events chan Message
	done   chan struct{}

	writeMu sync.Mutex
	closeMu sync.Once
	workers sync.WaitGroup
}

func Dial(ctx context.Context, brokerURL string) (*Client, error) {
	wsURL, err := normalizeBrokerURL(brokerURL)
	if err != nil {
		return nil, err
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	header := http.Header{}
	conn, _, err := dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		return nil, fmt.Errorf("dial broker: %w", err)
	}
	conn.SetReadLimit(maxBrokerMessageBytes)

	client := &Client{
		conn:   conn,
		events: make(chan Message, 32),
		done:   make(chan struct{}),
	}

	// Arm read deadline and refresh it on every pong. The pong handler
	// runs inside ReadJSON/NextReader, so this is race-free with the
	// read loop.
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return client.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})

	client.workers.Add(3)
	go client.readLoop()
	go client.pingLoop()
	go client.appPingLoop()
	return client, nil
}

func (c *Client) Events() <-chan Message {
	return c.events
}

func (c *Client) Register(ctx context.Context, register Register) error {
	return c.send(ctx, Message{
		Type:     MessageTypeRegister,
		Register: &register,
	})
}

func (c *Client) SendSignal(ctx context.Context, signal Signal) error {
	return c.send(ctx, Message{
		Type:   MessageTypeSignal,
		Signal: &signal,
	})
}

func (c *Client) Close() error {
	var err error
	c.closeMu.Do(func() {
		close(c.done)
		err = c.conn.Close()
	})
	c.workers.Wait()
	return err
}

func (c *Client) send(ctx context.Context, message Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
	} else {
		if err := c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait)); err != nil {
			return err
		}
	}

	if err := c.conn.WriteJSON(message); err != nil {
		return fmt.Errorf("write broker message: %w", err)
	}

	return nil
}

func (c *Client) readLoop() {
	defer c.workers.Done()
	defer close(c.events)
	for {
		select {
		case <-c.done:
			return
		default:
		}

		var message Message
		if err := c.conn.ReadJSON(&message); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return
			}

			select {
			case c.events <- Message{
				Type: MessageTypeError,
				Error: &ErrorPayload{
					Code:    "broker-read",
					Message: err.Error(),
				},
			}:
			default:
			}
			return
		}

		// Any inbound frame is evidence of a live connection; refresh
		// the read deadline. Pong handler already does this for pongs,
		// but application messages count too.
		_ = c.conn.SetReadDeadline(time.Now().Add(wsPongWait))

		// Swallow broker-originated pings (we echo them as pongs)
		// and pongs (liveness accounting only) so they never reach
		// the peer event loop.
		switch message.Type {
		case MessageTypePing:
			c.replyPong(message)
			continue
		case MessageTypePong:
			continue
		}

		select {
		case c.events <- message:
		case <-c.done:
			return
		}
	}
}

// replyPong responds to an application-level ping with an echoed
// pong. Errors are silent — the ping loop on either side will detect
// a broken connection via its own write, and the broker doesn't
// require a pong to stay happy.
func (c *Client) replyPong(ping Message) {
	var token string
	if ping.Ping != nil {
		token = ping.Ping.Token
	}
	ctx, cancel := context.WithTimeout(context.Background(), wsWriteWait)
	defer cancel()
	_ = c.send(ctx, Message{Type: MessageTypePong, Pong: &Pong{Token: token}})
}

// appPingLoop drives a periodic application-level ping JSON message.
// Unlike WebSocket ping frames, application frames always count as
// liveness to every intermediary — essential for cloudflared, which
// tunnels traffic over QUIC and has been observed to ignore WS
// control frames for idle accounting.
func (c *Client) appPingLoop() {
	defer c.workers.Done()
	ticker := time.NewTicker(appPingInterval)
	defer ticker.Stop()
	seq := uint64(0)
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			seq++
			ctx, cancel := context.WithTimeout(context.Background(), wsWriteWait)
			err := c.send(ctx, Message{
				Type: MessageTypePing,
				Ping: &Ping{Token: strconv.FormatUint(seq, 10)},
			})
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// pingLoop drives a periodic WebSocket ping so intermediaries (reverse
// proxies, tunnels) don't idle-timeout the connection while the
// WebRTC DataChannel is carrying the actual payload. Exits on c.done
// or the first write failure.
func (c *Client) pingLoop() {
	defer c.workers.Done()
	ticker := time.NewTicker(wsPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.writeMu.Lock()
			err := c.conn.WriteControl(
				websocket.PingMessage,
				nil,
				time.Now().Add(wsWriteWait),
			)
			c.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func normalizeBrokerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("broker URL is required")
	}

	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse broker URL: %w", err)
	}

	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported broker URL scheme %q", parsed.Scheme)
	}

	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/ws"
	}

	if parsed.Scheme == "ws" && !isLocalBrokerHost(parsed.Hostname()) {
		return "", errors.New("insecure broker transport is only allowed for localhost")
	}

	return parsed.String(), nil
}

func MarshalSignal(signal Signal) ([]byte, error) {
	return json.Marshal(Message{
		Type:   MessageTypeSignal,
		Signal: &signal,
	})
}

func isLocalBrokerHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
