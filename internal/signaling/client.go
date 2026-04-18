package signaling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const maxBrokerMessageBytes = 1 << 20

type Client struct {
	conn   *websocket.Conn
	events chan Message
	done   chan struct{}

	writeMu sync.Mutex
	closeMu sync.Once
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

	go client.readLoop()
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
		if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
	}

	if err := c.conn.WriteJSON(message); err != nil {
		return fmt.Errorf("write broker message: %w", err)
	}

	return nil
}

func (c *Client) readLoop() {
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

		select {
		case c.events <- message:
		case <-c.done:
			return
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
