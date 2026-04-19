package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	pion "github.com/pion/webrtc/v4"

	"github.com/haltman-io/rtc2tcp/internal/auth"
	"github.com/haltman-io/rtc2tcp/internal/banner"
	"github.com/haltman-io/rtc2tcp/internal/color"
	"github.com/haltman-io/rtc2tcp/internal/config"
	"github.com/haltman-io/rtc2tcp/internal/logx"
	"github.com/haltman-io/rtc2tcp/internal/rendezvous"
	"github.com/haltman-io/rtc2tcp/internal/signaling"
	"github.com/haltman-io/rtc2tcp/internal/socks5"
	"github.com/haltman-io/rtc2tcp/internal/tunnel"
	rtcwebrtc "github.com/haltman-io/rtc2tcp/internal/webrtc"
)

const (
	toolName         = "rtc2tcp-peer"
	defaultSTUN      = "stun:stun.l.google.com:19302"
	defaultListen    = "127.0.0.1:2222"
	authTimeout      = 45 * time.Second
	brokerSendTimout = 10 * time.Second
)

type app struct {
	logger  *log.Logger
	build   config.BuildInfo
	stderr  io.Writer
	quiet   bool
	noColor bool
	palette *color.Palette
}

func main() {
	stderr := os.Stderr
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	build := config.CurrentBuild()

	// Stop the terminal from echoing accidental keystrokes over our
	// output (click-to-position-cursor in Mintty/ConEmu/WSL emits arrow
	// keys on mouse click). Canonical mode and ISIG stay on — Ctrl+C
	// still works. Restore fires on normal return and on the error path
	// before os.Exit.
	restoreTTY := silenceTTYEcho()

	app := &app{
		logger: logger,
		build:  build,
		stderr: stderr,
	}
	app.refreshPalette()

	if err := app.run(os.Args[1:]); err != nil {
		restoreTTY()
		if !errors.Is(err, flag.ErrHelp) {
			logger.Print(logx.Event("peer", "run_failed", "err", err.Error()))
			app.printError(err)
		}
		os.Exit(1)
	}
	restoreTTY()
}

// refreshPalette recomputes the colour palette based on --no-color and
// TTY detection. Called once at startup and again after the subcommand
// parser has toggled a.noColor.
func (a *app) refreshPalette() {
	a.palette = color.New(!a.noColor && color.Detect(a.stderr))
}

func (a *app) run(args []string) error {
	// Peek global flags before subcommand dispatch so the banner is
	// suppressed early on `--quiet`/`-q`/`--silent` and does not
	// render colours under `--no-color`.
	a.quiet = peekBool(args, "quiet", "silent", "q")
	a.noColor = peekBool(args, "no-color")
	a.refreshPalette()

	if len(args) == 0 {
		a.showBanner("")
		a.printRootUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "expose":
		return a.runSubcommand(config.ModeExpose, args[1:])
	case "connect":
		return a.runSubcommand(config.ModeConnect, args[1:])
	case "-h", "--help", "help":
		a.showBanner("")
		a.printRootUsage()
		return nil
	case "-v", "-V", "-version", "--version", "version":
		fmt.Fprintln(os.Stdout, banner.VersionLine(toolName, a.build))
		return nil
	default:
		a.showBanner("")
		a.printRootUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func (a *app) runSubcommand(mode config.PeerMode, args []string) error {
	options, versionOnly, err := a.parsePeerFlags(mode, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if versionOnly {
		fmt.Fprintln(os.Stdout, banner.VersionLine(toolName, a.build))
		return nil
	}
	return a.runPeer(options)
}

func (a *app) runPeer(options config.PeerOptions) error {
	if err := options.Validate(); err != nil {
		return err
	}

	rendezvousToken, err := rendezvous.ValidateToken(options.RendezvousToken)
	if err != nil {
		return err
	}

	authenticator, err := auth.NewInteractiveAuthenticator(options.PairingSecret)
	if err != nil {
		return err
	}

	// Structural downgrade guard. The peer binary is built to require
	// the CPACE-Ristretto255 scheme; if a future refactor of
	// NewInteractiveAuthenticator silently returns a weaker scheme,
	// fail loudly at startup rather than authenticating over it.
	if authenticator.Name() != auth.SchemeCPACEV2 {
		return fmt.Errorf("peer requires auth scheme %q, got %q", auth.SchemeCPACEV2, authenticator.Name())
	}

	a.showBanner(string(options.Mode))
	if options.Mode == config.ModeExpose {
		a.printExposeHandoff(options)
	} else {
		a.printConnectSummary(options)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client, err := signaling.Dial(ctx, options.BrokerURL)
	if err != nil {
		return err
	}
	defer client.Close()

	registerCtx, registerCancel := context.WithTimeout(ctx, brokerSendTimout)
	defer registerCancel()

	if err := client.Register(registerCtx, signaling.Register{
		RendezvousToken: rendezvousToken,
		Mode:            options.Mode.String(),
		Version:         a.build.Version,
	}); err != nil {
		return err
	}

	a.event("rendezvous_registered", "mode", options.Mode, "broker", options.BrokerURL)
	a.info("Registered with broker; waiting for peer…")

	var (
		session          *rtcwebrtc.Session
		stateMachine     = rtcwebrtc.NewStateMachine()
		authResultCh     chan error
		listenerResultCh chan error
		listenerStarted  bool
		streamCounter    uint64
	)

	defer func() {
		if session != nil {
			_ = session.Close()
		}
	}()

	if err := stateMachine.Transition(rtcwebrtc.StateRendezvous); err != nil {
		return err
	}

	startListener := func() {
		if listenerStarted || options.Mode != config.ModeConnect {
			return
		}
		listenerStarted = true
		listenerResultCh = make(chan error, 1)
		go func() {
			if options.SOCKS5 {
				listenerResultCh <- a.runSOCKS5Listener(ctx, options.Listen, session, &streamCounter)
			} else {
				listenerResultCh <- a.runListener(ctx, options.Listen, session, &streamCounter)
			}
		}()
	}

	failSession := func(err error) error {
		if session != nil {
			_ = session.Fail(err)
		}
		return err
	}

	// brokerEvents is the live events channel; it's nilled out below
	// once the WebRTC tunnel is authenticated and the broker socket
	// dies. A nil channel in a select blocks forever, which is exactly
	// what we want: the tunnel keeps running off WebRTC alone.
	brokerEvents := client.Events()

	// postAuth reports whether the peer has reached a state where the
	// broker WebSocket is no longer in the critical path — once auth
	// succeeds and the WebRTC DataChannel is carrying traffic,
	// signaling is done and a lost broker socket should not tear down
	// a working tunnel.
	postAuth := func() bool {
		return stateMachine.IsOneOf(rtcwebrtc.StateAuthenticated, rtcwebrtc.StateStreaming)
	}

	// onBrokerLoss logs the event, detaches the broker events channel,
	// and returns nil (non-fatal). Only safe to call after postAuth().
	onBrokerLoss := func(reason string) {
		a.event("broker_detached", "reason", reason)
		a.warn("Broker connection lost (%s); tunnel continues over WebRTC.", reason)
		brokerEvents = nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-authResultCh:
			if err != nil {
				a.logAuthFailure(options.Mode, authenticator.Name(), err)
				a.printError(fmt.Errorf("authentication failed: %w", err))
				if session != nil {
					_ = session.Fail(fmt.Errorf("authentication did not complete: %w", err))
				}
				return err
			}
			a.event("session_ready", "mode", options.Mode)
			a.success("Authenticated with remote peer.")
			startListener()
			if options.Mode == config.ModeExpose {
				if options.SOCKS5 {
					a.event("expose_ready_socks5")
					a.info("SOCKS5 mode: resolving targets per stream from connect peer.")
				} else {
					a.event("expose_ready", "target", options.Target)
					a.info("Forwarding inbound streams to %s.", options.Target)
				}
			}
		case err := <-listenerResultCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				return failSession(err)
			}
			return nil
		case message, ok := <-brokerEvents:
			if !ok {
				if postAuth() {
					onBrokerLoss("events channel closed")
					continue
				}
				return failSession(errors.New("broker connection closed"))
			}

			switch message.Type {
			case signaling.MessageTypeRegistered:
				if message.Registered != nil {
					a.event("peer_id_assigned", "peer_id", message.Registered.PeerID)
				}
			case signaling.MessageTypePaired:
				if message.Paired == nil {
					return errors.New("broker paired message missing payload")
				}
				if session != nil {
					return errors.New("received duplicate paired message")
				}
				if err := stateMachine.Transition(rtcwebrtc.StateSignaling); err != nil {
					return err
				}

				session, err = a.newSession(ctx, client, stateMachine, options, authenticator, *message.Paired)
				if err != nil {
					return failSession(err)
				}

				a.info("Paired with peer, session %s — running CPACE handshake…", message.Paired.SessionID)

				authResultCh = make(chan error, 1)
				go func() {
					authCtx, cancel := context.WithTimeout(ctx, authTimeout)
					defer cancel()
					authResultCh <- session.WaitAuthenticated(authCtx)
				}()

				if message.Paired.Initiator {
					offer, err := session.CreateOffer(ctx)
					if err != nil {
						return failSession(err)
					}
					if err := a.sendSignal(ctx, client, signaling.Signal{
						Kind: signaling.SignalKindOffer,
						SDP: &signaling.SDPPayload{
							Type: "offer",
							SDP:  offer,
						},
					}); err != nil {
						return failSession(err)
					}
					a.event("offer_sent", "session_id", message.Paired.SessionID)
				}
			case signaling.MessageTypeSignal:
				if message.Signal == nil {
					return failSession(errors.New("signal message missing payload"))
				}
				if session == nil {
					return errors.New("received signal before pairing")
				}
				if err := a.handleSignal(ctx, client, session, *message.Signal); err != nil {
					return failSession(err)
				}
			case signaling.MessageTypePeerLeft:
				reason := "peer left"
				if message.PeerLeft != nil && message.PeerLeft.Reason != "" {
					reason = message.PeerLeft.Reason
				}
				// PeerLeft only fires for the remote WebRTC peer going
				// away. Always fatal regardless of state — there is no
				// tunnel to preserve once the other side is gone.
				if session != nil {
					_ = session.Fail(fmt.Errorf("peer left: %s", reason))
				}
				return fmt.Errorf("broker reported session end: %s", reason)
			case signaling.MessageTypeError:
				if message.Error == nil {
					return failSession(errors.New("broker returned an unspecified error"))
				}
				// Synthesised by the signaling client when the
				// WebSocket itself fails. Once we're past auth the
				// broker isn't in the data path — log and drop, keep
				// forwarding over WebRTC.
				if message.Error.Code == "broker-read" && postAuth() {
					onBrokerLoss(fmt.Sprintf("broker-read: %s", message.Error.Message))
					continue
				}
				return failSession(fmt.Errorf("broker error [%s]: %s", message.Error.Code, message.Error.Message))
			default:
				a.event("unexpected_broker_message", "type", message.Type)
			}
		}
	}
}

func (a *app) newSession(ctx context.Context, client *signaling.Client, stateMachine *rtcwebrtc.StateMachine, options config.PeerOptions, authenticator auth.Authenticator, paired signaling.Paired) (*rtcwebrtc.Session, error) {
	var onStream func(*pion.DataChannel)
	if options.Mode == config.ModeExpose {
		onStream = func(dc *pion.DataChannel) {
			a.handleExposeStream(options.Target, options.SOCKS5, dc)
		}
	}

	session, err := rtcwebrtc.NewSession(rtcwebrtc.Config{
		Logger:        a.logger,
		Mode:          options.Mode,
		SessionID:     paired.SessionID,
		Initiator:     paired.Initiator,
		ICE:           options.ICE,
		Authenticator: authenticator,
		StateMachine:  stateMachine,
		OnSignal: func(signal signaling.Signal) {
			sendCtx, cancel := context.WithTimeout(ctx, brokerSendTimout)
			defer cancel()
			if err := a.sendSignal(sendCtx, client, signal); err != nil {
				a.event("signal_dispatch_failed", "kind", signal.Kind, "err", err.Error())
			}
		},
		OnStream: onStream,
	})
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (a *app) handleSignal(ctx context.Context, client *signaling.Client, session *rtcwebrtc.Session, signal signaling.Signal) error {
	switch signal.Kind {
	case signaling.SignalKindOffer:
		if signal.SDP == nil {
			return errors.New("offer payload is required")
		}
		answer, err := session.HandleOffer(ctx, signal.SDP.SDP)
		if err != nil {
			return err
		}
		if err := a.sendSignal(ctx, client, signaling.Signal{
			Kind: signaling.SignalKindAnswer,
			SDP: &signaling.SDPPayload{
				Type: "answer",
				SDP:  answer,
			},
		}); err != nil {
			return err
		}
		a.event("answered_remote_offer")
	case signaling.SignalKindAnswer:
		if signal.SDP == nil {
			return errors.New("answer payload is required")
		}
		if err := session.HandleAnswer(ctx, signal.SDP.SDP); err != nil {
			return err
		}
		a.event("applied_remote_answer")
	case signaling.SignalKindICE:
		if signal.Candidate == nil {
			return errors.New("ICE candidate payload is required")
		}
		if err := session.AddRemoteCandidate(*signal.Candidate); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported signal kind %q", signal.Kind)
	}
	return nil
}

func (a *app) handleExposeStream(target string, socks5Mode bool, dc *pion.DataChannel) {
	dc.OnOpen(func() {
		// Dial off the pion callback goroutine: DialTimeout can block for
		// seconds, and starving pion's dispatcher stalls every other
		// channel on this PeerConnection.
		go func() {
			actualTarget := target
			if socks5Mode {
				// In SOCKS5 mode the connect peer encodes the target in
				// the channel label as "socks5-N|host:port". The expose
				// peer resolves the target from the label so no extra
				// protocol round-trip is needed.
				t, err := parseSocks5Label(dc.Label())
				if err != nil {
					a.event("socks5_bad_label", "label", dc.Label(), "err", err.Error())
					_ = dc.Close()
					return
				}
				actualTarget = t
			}
			a.event("inbound_stream_opened", "label", dc.Label(), "target", actualTarget)
			conn, err := net.DialTimeout("tcp", actualTarget, 10*time.Second)
			if err != nil {
				a.event("target_dial_failed", "target", actualTarget, "err", err.Error())
				_ = dc.Close()
				return
			}
			// In SOCKS5 mode the connect peer is waiting for a ready
			// signal before it sends the SOCKS5 success reply to the
			// client. Send the signal now so dc.OnMessage (set by
			// Bridge below) is registered before the client's first
			// bytes arrive on the channel.
			if socks5Mode {
				if sendErr := dc.Send([]byte{0x01}); sendErr != nil {
					a.event("socks5_ready_signal_failed", "label", dc.Label(), "err", sendErr.Error())
					_ = conn.Close()
					_ = dc.Close()
					return
				}
			}
			tunnel.Bridge(a.logger, dc, conn)
		}()
	})
}

// parseSocks5Label extracts the target address from a SOCKS5 channel
// label produced by runSOCKS5Listener. Labels have the form
// "socks5-N|host:port"; the pipe separates the stream counter from the
// target so IPv6 colons in "host:port" are unambiguous.
func parseSocks5Label(label string) (string, error) {
	idx := strings.Index(label, "|")
	if idx < 0 || idx == len(label)-1 {
		return "", fmt.Errorf("malformed socks5 channel label %q", label)
	}
	return label[idx+1:], nil
}

func (a *app) runListener(ctx context.Context, listen string, session *rtcwebrtc.Session, counter *uint64) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	defer listener.Close()

	a.event("listening", "addr", listen)
	a.success("Listening on %s — forward clients through this address.", listen)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("accept local connection: %w", err)
		}

		streamID := atomic.AddUint64(counter, 1)
		label := "tcp-" + strconv.FormatUint(streamID, 10)
		dc, err := session.OpenStreamChannel(label)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("open stream channel %s: %w", label, err)
		}

		a.event("local_accept", "stream", label)
		dc.OnOpen(func() {
			tunnel.Bridge(a.logger, dc, conn)
		})
	}
}

// runSOCKS5Listener accepts SOCKS5 CONNECT requests on listen and opens
// a new data channel per connection. The target is encoded in the channel
// label so the expose peer can dial it without an extra round-trip. Each
// accepted connection is handled in its own goroutine so a slow SOCKS5
// handshake cannot stall other concurrent connections.
func (a *app) runSOCKS5Listener(ctx context.Context, listen string, session *rtcwebrtc.Session, counter *uint64) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	defer listener.Close()

	a.event("socks5_listening", "addr", listen)
	a.success("SOCKS5 proxy listening on %s — configure your client to use this address.", listen)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("accept SOCKS5 connection: %w", err)
		}
		go a.handleSOCKS5Connect(conn, session, counter)
	}
}

// handleSOCKS5Connect performs the SOCKS5 handshake, opens a data channel
// to the expose peer with the target encoded in the label, and bridges
// traffic once both sides are ready. It is always run in its own goroutine.
func (a *app) handleSOCKS5Connect(conn net.Conn, session *rtcwebrtc.Session, counter *uint64) {
	target, err := socks5.Handshake(conn)
	if err != nil {
		a.event("socks5_handshake_failed", "err", err.Error())
		_ = conn.Close()
		return
	}

	streamID := atomic.AddUint64(counter, 1)
	// Encode target in the label using "|" as separator. "|" does not
	// appear in valid "host:port" strings, which makes IPv6 bracket
	// notation unambiguous (e.g. "socks5-1|[::1]:443").
	label := fmt.Sprintf("socks5-%d|%s", streamID, target)

	dc, err := session.OpenStreamChannel(label)
	if err != nil {
		socks5.ReplyFailure(conn)
		_ = conn.Close()
		a.event("socks5_stream_open_failed", "target", target, "err", err.Error())
		return
	}

	a.event("socks5_connecting", "stream", label, "target", target)
	dc.OnOpen(func() {
		// The expose peer dials the target asynchronously and only
		// calls dc.Send (the ready signal) after Bridge is set up on
		// its side. Register a temporary OnMessage handler that waits
		// for that signal so we do not send the SOCKS5 success reply
		// before the expose side has registered its dc.OnMessage.
		// Without this, the client's first HTTP bytes arrive on the
		// channel before pion has a handler and are silently dropped.
		readyCh := make(chan struct{}, 1)
		dc.OnMessage(func(_ pion.DataChannelMessage) {
			select {
			case readyCh <- struct{}{}:
			default:
			}
		})
		go func() {
			select {
			case <-readyCh:
			case <-time.After(15 * time.Second):
				a.event("socks5_ready_timeout", "stream", label, "target", target)
				_ = conn.Close()
				_ = dc.Close()
				return
			}
			// Bridge first: overwrites the temporary OnMessage handler
			// with the real one before the client gets the success reply
			// and starts sending data.
			tunnel.Bridge(a.logger, dc, conn)
			if err := socks5.ReplySuccess(conn); err != nil {
				_ = conn.Close()
				_ = dc.Close()
			}
		}()
	})
}

func (a *app) sendSignal(ctx context.Context, client *signaling.Client, signal signaling.Signal) error {
	if client == nil {
		return errors.New("broker client is required")
	}

	sendCtx, cancel := context.WithTimeout(ctx, brokerSendTimout)
	defer cancel()
	return client.SendSignal(sendCtx, signal)
}

// parsePeerFlags handles both subcommands. It registers long flags plus
// short single-letter aliases via the stdlib `flag` package (multiple
// registrations with the same pointer target). The connect subcommand
// additionally accepts an optional positional `rtc2tcp://…` connection
// string as the first argument.
func (a *app) parsePeerFlags(mode config.PeerMode, args []string) (config.PeerOptions, bool, error) {
	defaultBroker := a.build.DefaultBrokerURL
	if defaultBroker == "" {
		defaultBroker = "https://rtc.haltman.io/"
	}

	fs := flag.NewFlagSet(mode.String(), flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	options := config.PeerOptions{
		Mode: mode,
		ICE: config.ICEConfig{
			STUN: defaultSTUN,
		},
		BrokerURL: defaultBroker,
	}

	var (
		versionOnly       bool
		pairingSecret     string
		pairingSecretFile string
		legacySecret      string
		legacySecretFile  string
		connectionString  string
	)

	// Long flags + environment.
	fs.StringVar(&options.RendezvousToken, "rendezvous-token", "", "broker-visible pairing token (auto-generated on expose if unset; required on connect)")
	fs.StringVar(&pairingSecret, "pairing-secret", "", "peer pairing secret (auto-generated on expose if unset; prefer --pairing-secret-file)")
	fs.StringVar(&pairingSecretFile, "pairing-secret-file", "", "read pairing secret from file (preferred over --pairing-secret)")
	fs.StringVar(&legacySecret, "secret", "", "deprecated alias for --pairing-secret")
	fs.StringVar(&legacySecretFile, "secret-file", "", "deprecated alias for --pairing-secret-file")
	fs.StringVar(&options.BrokerURL, "broker", options.BrokerURL, "broker URL, e.g. http://127.0.0.1:8080 or wss://broker.example.com")
	fs.StringVar(&options.ICE.STUN, "stun", options.ICE.STUN, "STUN server URL (set empty to disable)")
	fs.StringVar(&options.ICE.TURN, "turn", "", "TURN server URL, e.g. turn:turn.example.net:3478?transport=udp")
	fs.StringVar(&options.ICE.TURNUsername, "turn-username", "", "TURN username")
	fs.StringVar(&options.ICE.TURNPassword, "turn-password", "", "TURN password")
	fs.StringVar(&connectionString, "connection", "", "rtc2tcp://token:secret@host[:port] connection string (connect mode)")
	fs.BoolVar(&versionOnly, "version", false, "print version and exit")
	fs.BoolVar(&a.quiet, "quiet", false, "suppress banner and informational output")
	fs.BoolVar(&a.quiet, "silent", false, "alias for --quiet")
	fs.BoolVar(&a.noColor, "no-color", false, "disable ANSI colors")

	// Short aliases, same target pointers.
	fs.StringVar(&options.RendezvousToken, "t", "", "alias for --rendezvous-token")
	fs.StringVar(&pairingSecret, "s", "", "alias for --pairing-secret")
	fs.StringVar(&options.BrokerURL, "b", options.BrokerURL, "alias for --broker")
	fs.BoolVar(&versionOnly, "V", false, "alias for --version")
	fs.BoolVar(&a.quiet, "q", false, "alias for --quiet")

	switch mode {
	case config.ModeExpose:
		fs.StringVar(&options.Target, "target", "", "local TCP target to expose, e.g. 127.0.0.1:22 (required unless --socks5)")
		fs.StringVar(&options.Target, "T", "", "alias for --target")
		fs.BoolVar(&options.SOCKS5, "socks5", false, "accept dynamic targets per stream; connect peer must also pass --socks5")
	case config.ModeConnect:
		fs.StringVar(&options.Listen, "listen", defaultListen, "local TCP address where the remote target surfaces, e.g. 127.0.0.1:2222")
		fs.StringVar(&options.Listen, "l", defaultListen, "alias for --listen")
		fs.BoolVar(&options.SOCKS5, "socks5", false, "listen as a SOCKS5 proxy; expose peer must also pass --socks5")
	}

	fs.Usage = func() {
		a.showBanner(string(mode))
		a.printSubcommandUsage(mode)
	}

	// Peel off a positional connection string for connect mode.
	if mode == config.ModeConnect && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		connectionString = args[0]
		args = args[1:]
	}

	if err := fs.Parse(args); err != nil {
		return config.PeerOptions{}, false, err
	}
	a.refreshPalette()

	if versionOnly {
		return options, true, nil
	}

	// Mode-specific required fields. Fail here, before the banner and
	// the credential auto-gen block run, so the user sees one clean
	// error line instead of a freshly-minted token followed by a
	// "target is required" message.
	switch mode {
	case config.ModeExpose:
		if !options.SOCKS5 && strings.TrimSpace(options.Target) == "" {
			return config.PeerOptions{}, false, errors.New("expose mode requires --target HOST:PORT or --socks5")
		}
	}

	// Connection string overrides only those fields the user has not
	// explicitly passed.
	if strings.TrimSpace(connectionString) != "" {
		cs, err := config.ParseConnectionString(connectionString)
		if err != nil {
			return config.PeerOptions{}, false, fmt.Errorf("parse --connection: %w", err)
		}
		if strings.TrimSpace(options.RendezvousToken) == "" {
			options.RendezvousToken = cs.RendezvousToken
		}
		if pairingSecret == "" && pairingSecretFile == "" && legacySecret == "" && legacySecretFile == "" {
			pairingSecret = cs.PairingSecret
		}
		if options.BrokerURL == defaultBroker {
			options.BrokerURL = cs.BrokerURL
		}
	}

	// Token resolution. Auto-generated on expose if missing; required
	// (with a helpful message) on connect.
	options.RendezvousToken = config.ResolveRendezvousTokenOptional(options.RendezvousToken)
	if options.RendezvousToken == "" {
		if mode == config.ModeExpose {
			tok, err := config.RandomToken()
			if err != nil {
				return config.PeerOptions{}, false, fmt.Errorf("generate rendezvous token: %w", err)
			}
			options.RendezvousToken = tok
		} else {
			return config.PeerOptions{}, false, fmt.Errorf("rendezvous token is required: pass --rendezvous-token, --connection, set %s, or paste the rtc2tcp://… connection string", config.EnvRendezvousToken)
		}
	}

	// Pairing secret resolution. Same auto-gen rule.
	secret, err := config.ResolvePairingSecretOptional(pairingSecret, pairingSecretFile, legacySecret, legacySecretFile)
	if err != nil {
		return config.PeerOptions{}, false, err
	}
	if secret == "" {
		if mode == config.ModeExpose {
			gen, err := config.RandomToken()
			if err != nil {
				return config.PeerOptions{}, false, fmt.Errorf("generate pairing secret: %w", err)
			}
			secret = gen
		} else {
			return config.PeerOptions{}, false, fmt.Errorf("pairing secret is required: pass --pairing-secret, --pairing-secret-file, --connection, set %s/%s, or paste the rtc2tcp://… connection string", config.EnvPairingSecretFile, config.EnvPairingSecret)
		}
	}
	options.PairingSecret = secret

	return options, false, nil
}

// printExposeHandoff renders the auto-generated credentials and the
// one-liner connect command for the remote peer. This is the single
// most important UX moment: a user running `rtc2tcp-peer expose
// --target 127.0.0.1:22` must see, without scrolling or reading docs,
// exactly what to paste on the other machine.
func (a *app) printExposeHandoff(options config.PeerOptions) {
	if a.quiet {
		return
	}

	p := a.palette
	cs := config.ConnectionString{
		RendezvousToken: options.RendezvousToken,
		PairingSecret:   options.PairingSecret,
		BrokerURL:       options.BrokerURL,
	}
	formatted, err := cs.Format()
	if err != nil {
		a.printError(fmt.Errorf("format connection string: %w", err))
		return
	}

	fmt.Fprintln(a.stderr, p.Bold("Session credentials"))
	fmt.Fprintf(a.stderr, "  %s %s\n", p.Muted("rendezvous token:"), p.Cyan(options.RendezvousToken))
	fmt.Fprintf(a.stderr, "  %s %s\n", p.Muted("pairing secret  :"), p.Cyan(options.PairingSecret))
	fmt.Fprintf(a.stderr, "  %s %s\n", p.Muted("broker          :"), p.Cyan(options.BrokerURL))
	if options.SOCKS5 {
		fmt.Fprintf(a.stderr, "  %s %s\n", p.Muted("mode            :"), p.Cyan("socks5 (dynamic targets)"))
	} else {
		fmt.Fprintf(a.stderr, "  %s %s\n", p.Muted("target          :"), p.Cyan(options.Target))
	}
	fmt.Fprintln(a.stderr)
	fmt.Fprintln(a.stderr, p.Bold("Run this on the connecting machine:"))
	fmt.Fprintf(a.stderr, "  %s %s\n",
		p.Green(toolName+" connect"),
		p.Green(formatted),
	)
	fmt.Fprintln(a.stderr)
	fmt.Fprintln(a.stderr, p.Muted("The tunnel will surface on the connect side at 127.0.0.1:2222 by default."))
	fmt.Fprintln(a.stderr, p.Muted("Override with --listen HOST:PORT. Keep this terminal open; closing it ends the tunnel."))
	fmt.Fprintln(a.stderr)
}

func (a *app) printConnectSummary(options config.PeerOptions) {
	if a.quiet {
		return
	}
	p := a.palette
	fmt.Fprintln(a.stderr, p.Bold("Connecting"))
	fmt.Fprintf(a.stderr, "  %s %s\n", p.Muted("broker          :"), p.Cyan(options.BrokerURL))
	fmt.Fprintf(a.stderr, "  %s %s\n", p.Muted("rendezvous token:"), p.Cyan(options.RendezvousToken))
	fmt.Fprintf(a.stderr, "  %s %s\n", p.Muted("local listen    :"), p.Cyan(options.Listen))
	fmt.Fprintln(a.stderr)
}

// ---------- output helpers ----------

func (a *app) showBanner(role string) {
	banner.Print(a.stderr, banner.Options{
		Quiet:   a.quiet,
		NoColor: a.noColor,
		Build:   a.build,
		Tool:    toolName,
		Role:    role,
	})
}

func (a *app) info(format string, args ...any) {
	if a.quiet {
		return
	}
	fmt.Fprintf(a.stderr, "%s %s\n", a.palette.Info("[info]"), fmt.Sprintf(format, args...))
}

func (a *app) warn(format string, args ...any) {
	if a.quiet {
		return
	}
	fmt.Fprintf(a.stderr, "%s %s\n", a.palette.Warn("[warn]"), fmt.Sprintf(format, args...))
}

func (a *app) success(format string, args ...any) {
	if a.quiet {
		return
	}
	fmt.Fprintf(a.stderr, "%s %s\n", a.palette.Success("[ ok ]"), fmt.Sprintf(format, args...))
}

func (a *app) printError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(a.stderr, "%s %s\n", a.palette.Error("[err ]"), err.Error())
}

// event emits a structured peer log line via logx.Event.
func (a *app) event(event string, kv ...any) {
	a.logger.Print(logx.Event("peer", event, kv...))
}

// logAuthFailure emits a structured, operator-auditable line for every
// failed peer-authentication attempt. The line intentionally carries no
// pairing-secret-derived material: scheme, mode, and error class only.
func (a *app) logAuthFailure(mode config.PeerMode, scheme string, err error) {
	a.event("auth_failure",
		"mode", mode,
		"scheme", scheme,
		"reason", authFailureReason(err),
		"detail", err.Error(),
	)
}

func authFailureReason(err error) string {
	switch {
	case errors.Is(err, auth.ErrAuthSchemeMismatch):
		return "scheme_mismatch"
	case errors.Is(err, auth.ErrAuthRoleMismatch):
		return "role_mismatch"
	case errors.Is(err, auth.ErrAuthInvalidShare):
		return "invalid_share"
	case errors.Is(err, auth.ErrAuthConfirmationMismatch):
		return "confirmation_mismatch"
	case errors.Is(err, auth.ErrAuthUnexpectedKind):
		return "unexpected_kind"
	case errors.Is(err, auth.ErrAuthStateOutOfOrder):
		return "state_out_of_order"
	case errors.Is(err, auth.ErrAuthUnsupportedScheme):
		return "unsupported_scheme"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "unclassified"
	}
}

// ---------- help and usage ----------

func (a *app) printRootUsage() {
	w := a.stderr
	p := a.palette
	fmt.Fprintln(w, p.Bold("Usage:"))
	fmt.Fprintln(w, "  "+p.Cyan(toolName+" expose")+"  "+p.Bold("--target HOST:PORT")+" "+p.Muted("[flags]"))
	fmt.Fprintln(w, "  "+p.Cyan(toolName+" connect")+" "+p.Muted("[rtc2tcp://TOKEN:SECRET@HOST[:PORT]] [--listen HOST:PORT] [flags]"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.Bold("Subcommands:"))
	fmt.Fprintln(w, "  "+p.Cyan("expose")+"    Expose a local TCP endpoint to a remote peer. "+p.Muted("--target is required."))
	fmt.Fprintln(w, "  "+p.Cyan("connect")+"   Forward a local TCP address to a remote exposed service.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.Bold("Global flags:"))
	fmt.Fprintln(w, "  -q, --quiet, --silent    Suppress banner and informational output.")
	fmt.Fprintln(w, "      --no-color           Disable ANSI colours in output.")
	fmt.Fprintln(w, "  -V, --version            Print version and exit.")
	fmt.Fprintln(w, "  -h, --help               Show this help.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.Bold("Environment:"))
	fmt.Fprintln(w, "  "+config.EnvRendezvousToken+"        Fallback for --rendezvous-token.")
	fmt.Fprintln(w, "  "+config.EnvPairingSecret+"           Fallback for --pairing-secret.")
	fmt.Fprintln(w, "  "+config.EnvPairingSecretFile+"      Fallback for --pairing-secret-file.")
	fmt.Fprintln(w, "  NO_COLOR / FORCE_COLOR            Override colour detection.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.Bold("Examples:"))
	fmt.Fprintln(w, "  "+p.Muted("# expose side: share local SSH (credentials auto-generated):"))
	fmt.Fprintln(w, "  "+toolName+" expose --target 127.0.0.1:22")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+p.Muted("# connect side: surface the remote target on localhost:2223:"))
	fmt.Fprintln(w, "  "+toolName+" connect rtc2tcp://TOKEN:SECRET@broker.example.com:8080 --listen 127.0.0.1:2223")
	fmt.Fprintln(w, "  "+p.Muted("# then use the local port:"))
	fmt.Fprintln(w, "  ssh -p 2223 user@localhost")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+p.Muted("# Pinned credentials from environment:"))
	fmt.Fprintln(w, "  "+config.EnvRendezvousToken+"=lab-demo \\")
	fmt.Fprintln(w, "  "+config.EnvPairingSecretFile+"=./pairing-secret.txt \\")
	fmt.Fprintln(w, "  "+toolName+" connect --listen 127.0.0.1:2222")
	fmt.Fprintln(w)
}

func (a *app) printSubcommandUsage(mode config.PeerMode) {
	w := a.stderr
	p := a.palette
	switch mode {
	case config.ModeExpose:
		fmt.Fprintln(w, p.Bold("Usage: ")+p.Cyan(toolName+" expose")+" "+p.Bold("--target HOST:PORT")+p.Muted(" [flags]"))
		fmt.Fprintln(w)
		fmt.Fprintln(w, p.Bold("Expose flags:"))
		fmt.Fprintln(w, "  -T, --target       HOST:PORT      Local TCP endpoint to expose. "+p.Bold("(required)"))
		fmt.Fprintln(w)
	case config.ModeConnect:
		fmt.Fprintln(w, p.Bold("Usage: ")+p.Cyan(toolName+" connect")+p.Muted(" [rtc2tcp://TOKEN:SECRET@HOST[:PORT]] [--listen HOST:PORT] [flags]"))
		fmt.Fprintln(w)
		fmt.Fprintln(w, p.Bold("Connect flags:"))
		fmt.Fprintln(w, "  -l, --listen       HOST:PORT      Local TCP address where the remote target surfaces. (default 127.0.0.1:2222)")
		fmt.Fprintln(w, "      --connection   URL            rtc2tcp://… connection string (same as positional arg).")
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, p.Bold("Rendezvous / auth:"))
	fmt.Fprintln(w, "  -t, --rendezvous-token TOKEN      Broker-visible pairing token.")
	fmt.Fprintln(w, "  -s, --pairing-secret   SECRET     Peer pairing secret (prefer --pairing-secret-file).")
	fmt.Fprintln(w, "      --pairing-secret-file FILE    Read pairing secret from file.")
	fmt.Fprintln(w, "  -b, --broker           URL        Broker URL (default https://rtc.haltman.io/).")
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.Bold("Network:"))
	fmt.Fprintln(w, "      --stun             URL        STUN server (empty to disable).")
	fmt.Fprintln(w, "      --turn             URL        TURN server URL.")
	fmt.Fprintln(w, "      --turn-username    NAME       TURN username.")
	fmt.Fprintln(w, "      --turn-password    PASS       TURN password.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.Bold("Global:"))
	fmt.Fprintln(w, "  -q, --quiet, --silent             Suppress banner and informational output.")
	fmt.Fprintln(w, "      --no-color                    Disable ANSI colours.")
	fmt.Fprintln(w, "  -V, --version                     Print version and exit.")
	fmt.Fprintln(w, "  -h, --help                        Show this help.")
	fmt.Fprintln(w)
}

// peekBool scans raw argv for any of the listed bool-flag names (long
// or short form). Used to suppress the banner and colour defaults
// before the proper subcommand flag parser runs.
func peekBool(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == "-"+n || a == "--"+n || a == "-"+n+"=true" || a == "--"+n+"=true" {
				return true
			}
		}
	}
	return false
}
