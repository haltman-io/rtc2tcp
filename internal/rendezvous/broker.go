package rendezvous

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"

	"github.com/haltman-io/rtc2tcp/internal/config"
	"github.com/haltman-io/rtc2tcp/internal/signaling"
)

const (
	initialReadTimeout = 15 * time.Second
	writeTimeout       = 10 * time.Second
	maxReadBytes       = 1 << 20

	// DefaultWaiterTTL bounds how long a registered peer can sit
	// unpaired before the broker evicts it. Prevents a
	// register-and-ghost client from occupying a rendezvous_token slot.
	DefaultWaiterTTL = 5 * time.Minute
	// DefaultSessionTTL bounds the lifetime of a paired session on the
	// broker side. The broker never sees payload traffic, so this only
	// limits how long the broker remembers a pairing.
	DefaultSessionTTL = 1 * time.Hour
	// DefaultJanitorInterval is how often the broker sweeps for expired
	// waiters and sessions.
	DefaultJanitorInterval = 30 * time.Second

	// DefaultUpgradeRatePerMinute is the per-source-IP cap on
	// WebSocket upgrade attempts. Spreading 30/min averages one every
	// 2 seconds.
	DefaultUpgradeRatePerMinute = 30
	// DefaultUpgradeBurst is the burst size for per-IP upgrade
	// attempts: short spikes are tolerated before the steady-state rate
	// takes over.
	DefaultUpgradeBurst = 10
	// DefaultLimiterIdleTTL is how long an IP's limiter entry is kept
	// after the last request before it is evicted from the map. Bounds
	// memory growth under churn.
	DefaultLimiterIdleTTL = 1 * time.Hour
)

// Keepalive tunables. Stored atomically so tests can drive real time
// fast without racing against the keepalive goroutines. Production
// code should not mutate these after NewBroker.
//
// Why atomic: tests mutate these between cases while goroutines from
// previous cases may still be winding down. Under -race, even a write
// after a finished goroutine's read flags a race without a happens-
// before edge. atomic.Int64 provides that edge.
var (
	wsPingIntervalNS atomic.Int64
	wsPongWaitNS     atomic.Int64
	wsWriteWaitNS    atomic.Int64
)

func init() {
	wsPingIntervalNS.Store(int64(20 * time.Second))
	wsPongWaitNS.Store(int64(60 * time.Second))
	wsWriteWaitNS.Store(int64(10 * time.Second))
}

func wsPingInterval() time.Duration { return time.Duration(wsPingIntervalNS.Load()) }
func wsPongWait() time.Duration     { return time.Duration(wsPongWaitNS.Load()) }
func wsWriteWait() time.Duration    { return time.Duration(wsWriteWaitNS.Load()) }

type Broker struct {
	logger   *log.Logger
	upgrader websocket.Upgrader

	waiterTTL       time.Duration
	sessionTTL      time.Duration
	janitorInterval time.Duration
	limiterIdleTTL  time.Duration
	now             func() time.Time

	trustedProxies     []trustedNet
	trustedProxyHeader string

	ipLimiter *keyedLimiter

	mu        sync.Mutex
	waiting   map[string]*peer
	activeKey map[string]string
	sessions  map[string]*session

	stop     chan struct{}
	stopOnce sync.Once
	janitor  sync.WaitGroup
}

type peer struct {
	id            string
	mode          config.PeerMode
	rendezvousKey string
	version       string
	conn          *websocket.Conn
	createdAt     time.Time

	writeMu sync.Mutex
}

type session struct {
	id            string
	rendezvousKey string
	first         *peer
	second        *peer
	createdAt     time.Time
}

// Options configures optional broker behaviour. The zero value falls
// back to compiled-in defaults; NewBroker is the stable entry point
// and remains valid without options.
type Options struct {
	// TrustedProxies is a list of IP addresses or CIDR blocks
	// describing upstreams that are allowed to supply a forwarded
	// client IP via TrustedProxyHeader. Leave empty to disable
	// forwarded-for parsing entirely (the safe default for direct
	// internet exposure).
	TrustedProxies []string
	// TrustedProxyHeader names the HTTP header consulted when the
	// immediate peer is a trusted proxy. Supported values are
	// "X-Forwarded-For" (multi-hop, list-aware), "X-Real-IP", or a
	// vendor-specific variant such as "CF-Connecting-IP". Defaults to
	// "X-Forwarded-For" when TrustedProxies is non-empty.
	TrustedProxyHeader string
	// RatePerMinute overrides the per-source-IP upgrade rate. Zero or
	// negative values fall back to DefaultUpgradeRatePerMinute.
	RatePerMinute int
	// RateBurst overrides the per-source-IP burst size. Zero or
	// negative values fall back to DefaultUpgradeBurst.
	RateBurst int
}

func NewBroker(logger *log.Logger) *Broker {
	b, err := NewBrokerWithOptions(logger, Options{})
	if err != nil {
		// Options{} is always valid; this path is unreachable.
		panic(fmt.Sprintf("rendezvous: unexpected error from NewBrokerWithOptions: %v", err))
	}
	return b
}

// NewBrokerWithOptions is the configurable constructor. Use this when
// the broker is running behind a reverse proxy (so forwarded-for
// parsing can be enabled) or when rate-limit tuning is required.
func NewBrokerWithOptions(logger *log.Logger, opts Options) (*Broker, error) {
	if logger == nil {
		logger = log.Default()
	}

	trusted, err := ParseTrustedProxies(strings.Join(opts.TrustedProxies, ","))
	if err != nil {
		return nil, err
	}

	header := strings.TrimSpace(opts.TrustedProxyHeader)
	if header == "" && len(trusted) > 0 {
		header = "X-Forwarded-For"
	}

	ratePerMinute := opts.RatePerMinute
	if ratePerMinute <= 0 {
		ratePerMinute = DefaultUpgradeRatePerMinute
	}
	burst := opts.RateBurst
	if burst <= 0 {
		burst = DefaultUpgradeBurst
	}

	b := &Broker{
		logger: logger,
		upgrader: websocket.Upgrader{
			CheckOrigin: brokerCheckOrigin,
		},
		waiterTTL:          DefaultWaiterTTL,
		sessionTTL:         DefaultSessionTTL,
		janitorInterval:    DefaultJanitorInterval,
		limiterIdleTTL:     DefaultLimiterIdleTTL,
		now:                time.Now,
		trustedProxies:     trusted,
		trustedProxyHeader: header,
		ipLimiter: newKeyedLimiter(
			rate.Every(time.Minute/time.Duration(ratePerMinute)),
			burst,
		),
		waiting:   make(map[string]*peer),
		activeKey: make(map[string]string),
		sessions:  make(map[string]*session),
		stop:      make(chan struct{}),
	}

	b.janitor.Add(1)
	go b.runJanitor()
	return b, nil
}

// SetTimeouts overrides the default TTLs. Intended for tests; do not
// call from production code after the broker has started accepting
// connections.
func (b *Broker) SetTimeouts(waiter, session, interval time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if waiter > 0 {
		b.waiterTTL = waiter
	}
	if session > 0 {
		b.sessionTTL = session
	}
	if interval > 0 {
		b.janitorInterval = interval
	}
}

func (b *Broker) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", b.handleWebSocket)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func (b *Broker) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	sourceIP := clientIP(r, b.trustedProxies, b.trustedProxyHeader)
	if !b.ipLimiter.Allow(sourceIP, b.now()) {
		b.logger.Print(FormatEvent("rate_limited", "source_ip", sourceIP))
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	conn, err := b.upgrader.Upgrade(w, r, nil)
	if err != nil {
		b.logger.Print(FormatEvent("upgrade_failed", "source_ip", sourceIP, "err", err.Error()))
		return
	}
	conn.SetReadLimit(maxReadBytes)

	p, err := b.registerPeer(conn)
	if err != nil {
		b.logger.Print(FormatEvent("register_failed", "source_ip", sourceIP, "err", err.Error()))
		_ = writeAndClose(conn, signaling.Message{
			Type: signaling.MessageTypeError,
			Error: &signaling.ErrorPayload{
				Code:    "register-failed",
				Message: genericBrokerMessage("register-failed"),
			},
		})
		return
	}

	b.logger.Print(FormatEvent("registered",
		"peer_id", p.id,
		"mode", p.mode,
		"rendezvous_token", p.rendezvousKey,
		"source_ip", sourceIP,
	))

	// Arm the keepalive path: start sending pings and arm a pong-wait
	// read deadline. Any inbound frame (application message OR pong)
	// refreshes the deadline via the pong handler / post-read refresh
	// below. Must happen AFTER registerPeer has cleared the
	// initialReadTimeout it installed for the register handshake.
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait()))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait()))
	})
	pingDone := make(chan struct{})
	defer close(pingDone)
	go b.runPeerKeepalive(p, pingDone)

	defer func() {
		b.unregisterPeer(p, "peer disconnected")
		_ = p.conn.Close()
	}()

	if err := b.send(p, signaling.Message{
		Type: signaling.MessageTypeRegistered,
		Registered: &signaling.Registered{
			PeerID: p.id,
		},
	}); err != nil {
		b.logger.Print(FormatEvent("ack_failed", "peer_id", p.id, "err", err.Error()))
		return
	}

	if err := b.tryPair(p); err != nil {
		b.logger.Print(FormatEvent("pairing_failed",
			"peer_id", p.id,
			"rendezvous_token", p.rendezvousKey,
			"err", err.Error(),
		))
		_ = b.send(p, signaling.Message{
			Type: signaling.MessageTypeError,
			Error: &signaling.ErrorPayload{
				Code:    "pairing-failed",
				Message: genericBrokerMessage("pairing-failed"),
			},
		})
		return
	}

	for {
		var message signaling.Message
		if err := conn.ReadJSON(&message); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return
			}
			b.logger.Print(FormatEvent("read_failed", "peer_id", p.id, "err", err.Error()))
			return
		}

		// Any inbound application frame refreshes the read deadline —
		// the pong handler already does this for pongs, but a steady
		// stream of signals during ICE should also count as liveness.
		_ = conn.SetReadDeadline(time.Now().Add(wsPongWait()))

		switch message.Type {
		case signaling.MessageTypePing:
			// Application-level keepalive. Reply with a pong echoing
			// the client's token so it can correlate if desired.
			var token string
			if message.Ping != nil {
				token = message.Ping.Token
			}
			_ = b.send(p, signaling.Message{
				Type: signaling.MessageTypePong,
				Pong: &signaling.Pong{Token: token},
			})
			continue
		case signaling.MessageTypePong:
			// Unsolicited pong — liveness only, deadline already
			// refreshed above.
			continue
		case signaling.MessageTypeSignal:
			if message.Signal == nil {
				_ = b.send(p, brokerError("invalid-signal", "signal payload is required"))
				continue
			}
			if err := b.relaySignal(p, *message.Signal); err != nil {
				b.logger.Print(FormatEvent("relay_failed",
					"peer_id", p.id,
					"signal_kind", message.Signal.Kind,
					"err", err.Error(),
				))
				_ = b.send(p, brokerError("relay-failed", genericBrokerMessage("relay-failed")))
				return
			}
		default:
			_ = b.send(p, brokerError("unexpected-message", "only signal messages are allowed after registration"))
		}
	}
}

func (b *Broker) registerPeer(conn *websocket.Conn) (*peer, error) {
	if err := conn.SetReadDeadline(time.Now().Add(initialReadTimeout)); err != nil {
		return nil, err
	}

	var message signaling.Message
	if err := conn.ReadJSON(&message); err != nil {
		return nil, fmt.Errorf("read registration: %w", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}

	if message.Type != signaling.MessageTypeRegister || message.Register == nil {
		return nil, errors.New("first message must be a register request")
	}

	mode, err := config.ParsePeerMode(message.Register.Mode)
	if err != nil {
		return nil, err
	}

	key := strings.TrimSpace(message.Register.RendezvousToken)
	if key == "" {
		return nil, errors.New("rendezvous token is required")
	}

	id, err := randomID()
	if err != nil {
		return nil, err
	}

	return &peer{
		id:            id,
		mode:          mode,
		rendezvousKey: key,
		version:       strings.TrimSpace(message.Register.Version),
		conn:          conn,
		createdAt:     b.now(),
	}, nil
}

func (b *Broker) tryPair(p *peer) error {
	var (
		peerMessage signaling.Message
		other       *peer
	)

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, busy := b.activeKey[p.rendezvousKey]; busy {
		return errors.New("a session is already active for this rendezvous key")
	}

	waiting := b.waiting[p.rendezvousKey]
	if waiting == nil {
		b.waiting[p.rendezvousKey] = p
		return nil
	}

	if waiting.id == p.id {
		return errors.New("peer is already waiting")
	}

	if waiting.mode == p.mode {
		return errors.New("need exactly one expose peer and one connect peer per rendezvous key")
	}

	sessionID, err := randomID()
	if err != nil {
		return err
	}

	delete(b.waiting, p.rendezvousKey)
	b.activeKey[p.rendezvousKey] = sessionID

	s := &session{
		id:            sessionID,
		rendezvousKey: p.rendezvousKey,
		first:         waiting,
		second:        p,
		createdAt:     b.now(),
	}
	b.sessions[sessionID] = s

	initiatorForWaiting := waiting.mode == config.ModeConnect
	initiatorForPeer := p.mode == config.ModeConnect

	other = waiting
	peerMessage = signaling.Message{
		Type: signaling.MessageTypePaired,
		Paired: &signaling.Paired{
			SessionID: sessionID,
			Initiator: initiatorForPeer,
			PeerMode:  waiting.mode.String(),
		},
	}

	waitingMessage := signaling.Message{
		Type: signaling.MessageTypePaired,
		Paired: &signaling.Paired{
			SessionID: sessionID,
			Initiator: initiatorForWaiting,
			PeerMode:  p.mode.String(),
		},
	}

	go func() {
		if err := b.send(waiting, waitingMessage); err != nil {
			b.logger.Print(FormatEvent("pair_delivery_failed",
				"session_id", sessionID,
				"peer_id", waiting.id,
				"err", err.Error(),
			))
			b.unregisterPeer(waiting, "pair delivery failed")
		}
	}()
	go func() {
		if err := b.send(p, peerMessage); err != nil {
			b.logger.Print(FormatEvent("pair_delivery_failed",
				"session_id", sessionID,
				"peer_id", p.id,
				"err", err.Error(),
			))
			b.unregisterPeer(p, "pair delivery failed")
		}
	}()

	b.logger.Print(FormatEvent("paired",
		"session_id", sessionID,
		"rendezvous_token", p.rendezvousKey,
		"peer_a", waiting.id,
		"peer_a_mode", waiting.mode,
		"peer_b", p.id,
		"peer_b_mode", p.mode,
	))
	_ = other
	return nil
}

func (b *Broker) relaySignal(from *peer, signal signaling.Signal) error {
	target, _, err := b.sessionPeers(from)
	if err != nil {
		return err
	}

	return b.send(target, signaling.Message{
		Type:   signaling.MessageTypeSignal,
		Signal: &signal,
	})
}

func (b *Broker) unregisterPeer(p *peer, reason string) {
	if p == nil {
		return
	}

	b.mu.Lock()

	if waiting := b.waiting[p.rendezvousKey]; waiting != nil && waiting.id == p.id {
		delete(b.waiting, p.rendezvousKey)
		b.mu.Unlock()
		return
	}

	target, sessionID := b.findSessionPeerLocked(p)
	if sessionID == "" {
		b.mu.Unlock()
		return
	}

	s := b.sessions[sessionID]
	delete(b.sessions, sessionID)
	delete(b.activeKey, s.rendezvousKey)
	b.mu.Unlock()

	if target != nil {
		_ = b.send(target, signaling.Message{
			Type: signaling.MessageTypePeerLeft,
			PeerLeft: &signaling.PeerLeft{
				Reason: reason,
			},
		})
	}

	b.logger.Print(FormatEvent("session_closed",
		"session_id", sessionID,
		"peer_id", p.id,
		"reason", reason,
	))
}

func (b *Broker) sessionPeers(from *peer) (*peer, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	target, sessionID := b.findSessionPeerLocked(from)
	if sessionID == "" {
		return nil, "", errors.New("peer is not paired")
	}
	return target, sessionID, nil
}

func (b *Broker) findSessionPeerLocked(from *peer) (*peer, string) {
	for id, s := range b.sessions {
		switch from.id {
		case s.first.id:
			return s.second, id
		case s.second.id:
			return s.first, id
		}
	}
	return nil, ""
}

func (b *Broker) send(p *peer, message signaling.Message) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	if err := p.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	if err := p.conn.WriteJSON(message); err != nil {
		return err
	}
	return nil
}

func (b *Broker) Shutdown(ctx context.Context) error {
	b.stopOnce.Do(func() { close(b.stop) })

	done := make(chan struct{})
	go func() {
		b.janitor.Wait()
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, s := range b.sessions {
			_ = s.first.conn.Close()
			_ = s.second.conn.Close()
		}
		for _, p := range b.waiting {
			_ = p.conn.Close()
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// runJanitor periodically evicts waiters and sessions that exceed their
// configured TTL. It is the only goroutine that can close a peer's
// WebSocket from outside the main handler.
func (b *Broker) runJanitor() {
	defer b.janitor.Done()

	for {
		b.mu.Lock()
		interval := b.janitorInterval
		b.mu.Unlock()
		if interval <= 0 {
			return
		}
		select {
		case <-b.stop:
			return
		case <-time.After(interval):
		}
		b.evictStale()
	}
}

type evictedSession struct {
	id     string
	first  *peer
	second *peer
}

// collectStale removes expired waiters and sessions from the broker
// maps and returns the evicted peers/sessions so the caller can
// close their connections after the lock is released. This split
// keeps the map invariants testable without faking WebSocket conns.
func (b *Broker) collectStale() ([]*peer, []evictedSession) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	waiterCutoff := now.Add(-b.waiterTTL)
	sessionCutoff := now.Add(-b.sessionTTL)

	var waiters []*peer
	for key, p := range b.waiting {
		if p.createdAt.Before(waiterCutoff) {
			delete(b.waiting, key)
			waiters = append(waiters, p)
		}
	}

	var sessions []evictedSession
	for id, s := range b.sessions {
		if s.createdAt.Before(sessionCutoff) {
			delete(b.sessions, id)
			delete(b.activeKey, s.rendezvousKey)
			sessions = append(sessions, evictedSession{id: id, first: s.first, second: s.second})
		}
	}
	return waiters, sessions
}

func (b *Broker) evictStale() {
	waiters, sessions := b.collectStale()
	b.ipLimiter.Cleanup(b.now().Add(-b.limiterIdleTTL))

	for _, p := range waiters {
		b.logger.Print(FormatEvent("waiter_evicted", "peer_id", p.id, "mode", p.mode))
		_ = b.send(p, brokerError("waiter-expired", genericBrokerMessage("waiter-expired")))
		_ = p.conn.Close()
	}
	for _, es := range sessions {
		b.logger.Print(FormatEvent("session_evicted", "session_id", es.id))
		if es.first != nil {
			_ = b.send(es.first, brokerError("session-expired", genericBrokerMessage("session-expired")))
			_ = es.first.conn.Close()
		}
		if es.second != nil {
			_ = b.send(es.second, brokerError("session-expired", genericBrokerMessage("session-expired")))
			_ = es.second.conn.Close()
		}
	}
}

func brokerError(code, message string) signaling.Message {
	return signaling.Message{
		Type: signaling.MessageTypeError,
		Error: &signaling.ErrorPayload{
			Code:    code,
			Message: message,
		},
	}
}

// genericBrokerMessage maps a broker error code to a fixed,
// peer-facing message. Internal detail stays in broker logs and never
// reaches the other side of a WebSocket; this prevents raw Go error
// strings from leaking into remote stack traces, rendezvous probes, or
// offline correlation of broker state.
func genericBrokerMessage(code string) string {
	switch code {
	case "register-failed":
		return "registration rejected"
	case "pairing-failed":
		return "pairing rejected"
	case "relay-failed":
		return "signaling relay failed"
	case "invalid-signal":
		return "signal payload is required"
	case "unexpected-message":
		return "only signal messages are allowed after registration"
	case "waiter-expired":
		return "rendezvous waiter expired"
	case "session-expired":
		return "session expired"
	default:
		return "broker error"
	}
}

func randomID() (string, error) {
	var buf [18]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func writeAndClose(conn *websocket.Conn, message signaling.Message) error {
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	if err := conn.WriteJSON(message); err != nil {
		return err
	}
	return conn.Close()
}

func brokerCheckOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}

	originHost := canonicalHost(parsed.Hostname(), parsed.Port())
	requestHost, requestPort, err := net.SplitHostPort(r.Host)
	if err != nil {
		requestHost = r.Host
		requestPort = ""
	}

	return strings.EqualFold(originHost, canonicalHost(requestHost, requestPort))
}

func canonicalHost(host, port string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	port = strings.TrimSpace(port)
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// runPeerKeepalive drives broker → peer WebSocket pings at
// wsPingInterval. Exits when done is closed (peer handler returning)
// or on the first write failure. Runs one goroutine per connected
// peer; cheap compared to the session it protects.
func (b *Broker) runPeerKeepalive(p *peer, done <-chan struct{}) {
	ticker := time.NewTicker(wsPingInterval())
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			p.writeMu.Lock()
			err := p.conn.WriteControl(
				websocket.PingMessage,
				nil,
				time.Now().Add(wsWriteWait()),
			)
			p.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// remoteIP extracts the source IP from r.RemoteAddr, falling back to
// the whole string if it does not parse as host:port. Used as the
// keying function for the per-IP upgrade rate limiter.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || host == "" {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
