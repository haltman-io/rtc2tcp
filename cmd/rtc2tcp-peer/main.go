package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	pion "github.com/pion/webrtc/v4"

	"rtc2tcp/internal/auth"
	"rtc2tcp/internal/config"
	"rtc2tcp/internal/logx"
	"rtc2tcp/internal/rendezvous"
	"rtc2tcp/internal/signaling"
	"rtc2tcp/internal/tunnel"
	rtcwebrtc "rtc2tcp/internal/webrtc"
)

const (
	defaultSTUN      = "stun:stun.l.google.com:19302"
	authTimeout      = 45 * time.Second
	brokerSendTimout = 10 * time.Second
)

type app struct {
	logger *log.Logger
	build  config.BuildInfo
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	build := config.CurrentBuild()

	app := &app{
		logger: logger,
		build:  build,
	}

	if err := app.run(os.Args[1:]); err != nil {
		logger.Print(logx.Event("peer", "run_failed", "err", err.Error()))
		os.Exit(1)
	}
}

func (a *app) run(args []string) error {
	if len(args) == 0 {
		a.printRootUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "expose":
		options, versionOnly, err := a.parsePeerFlags(config.ModeExpose, args[1:])
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if versionOnly {
			a.printVersion()
			return nil
		}
		return a.runPeer(options)
	case "connect":
		options, versionOnly, err := a.parsePeerFlags(config.ModeConnect, args[1:])
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if versionOnly {
			a.printVersion()
			return nil
		}
		return a.runPeer(options)
	case "-h", "--help", "help":
		a.printRootUsage()
		return nil
	case "-version", "--version", "version":
		a.printVersion()
		return nil
	default:
		a.printRootUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
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
	// Remove this check only when introducing a deliberate and
	// documented scheme upgrade path.
	if authenticator.Name() != auth.SchemeCPACEV2 {
		return fmt.Errorf("peer requires auth scheme %q, got %q", auth.SchemeCPACEV2, authenticator.Name())
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
			listenerResultCh <- a.runListener(ctx, options.Listen, session, &streamCounter)
		}()
	}

	failSession := func(err error) error {
		if session != nil {
			_ = session.Fail(err)
		}
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-authResultCh:
			if err != nil {
				a.logAuthFailure(options.Mode, authenticator.Name(), err)
				if session != nil {
					_ = session.Fail(fmt.Errorf("authentication did not complete: %w", err))
				}
				return err
			}
			a.event("session_ready", "mode", options.Mode)
			startListener()
			if options.Mode == config.ModeExpose {
				a.event("expose_ready", "target", options.Target)
			}
		case err := <-listenerResultCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				return failSession(err)
			}
			return nil
		case message, ok := <-client.Events():
			if !ok {
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
				if session != nil {
					_ = session.Fail(fmt.Errorf("peer left: %s", reason))
				}
				return fmt.Errorf("broker reported session end: %s", reason)
			case signaling.MessageTypeError:
				if message.Error == nil {
					return failSession(errors.New("broker returned an unspecified error"))
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
			a.handleExposeStream(options.Target, dc)
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

func (a *app) handleExposeStream(target string, dc *pion.DataChannel) {
	dc.OnOpen(func() {
		// Dial off the pion callback goroutine: DialTimeout can block for
		// seconds, and starving pion's dispatcher stalls every other
		// channel on this PeerConnection.
		go func() {
			a.event("inbound_stream_opened", "label", dc.Label(), "target", target)
			conn, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				a.event("target_dial_failed", "target", target, "err", err.Error())
				_ = dc.Close()
				return
			}
			tunnel.Bridge(a.logger, dc, conn)
		}()
	})
}

func (a *app) runListener(ctx context.Context, listen string, session *rtcwebrtc.Session, counter *uint64) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	defer listener.Close()

	a.event("listening", "addr", listen)

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

func (a *app) sendSignal(ctx context.Context, client *signaling.Client, signal signaling.Signal) error {
	if client == nil {
		return errors.New("broker client is required")
	}

	sendCtx, cancel := context.WithTimeout(ctx, brokerSendTimout)
	defer cancel()
	return client.SendSignal(sendCtx, signal)
}

func (a *app) parsePeerFlags(mode config.PeerMode, args []string) (config.PeerOptions, bool, error) {
	defaultBroker := a.build.DefaultBrokerURL
	if defaultBroker == "" {
		defaultBroker = "http://127.0.0.1:8080"
	}

	fs := flag.NewFlagSet(mode.String(), flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	options := config.PeerOptions{
		Mode: mode,
		ICE: config.ICEConfig{
			STUN: defaultSTUN,
		},
		BrokerURL: defaultBroker,
	}

	var versionOnly bool
	var (
		pairingSecret     string
		pairingSecretFile string
		legacySecret      string
		legacySecretFile  string
	)

	fs.StringVar(&options.RendezvousToken, "rendezvous-token", "", "broker-visible pairing token; prefer a random opaque value or set "+config.EnvRendezvousToken)
	fs.StringVar(&pairingSecret, "pairing-secret", "", "peer pairing secret; prefer --pairing-secret-file or "+config.EnvPairingSecretFile)
	fs.StringVar(&pairingSecretFile, "pairing-secret-file", "", "path to the peer pairing secret file; preferred over direct CLI secret flags")
	fs.StringVar(&legacySecret, "secret", "", "deprecated alias for --pairing-secret")
	fs.StringVar(&legacySecretFile, "secret-file", "", "deprecated alias for --pairing-secret-file")
	fs.StringVar(&options.BrokerURL, "broker", options.BrokerURL, "broker URL, for example http://127.0.0.1:8080 or ws://127.0.0.1:8080/ws")
	fs.StringVar(&options.ICE.STUN, "stun", options.ICE.STUN, "STUN server URL, set to empty string to disable")
	fs.StringVar(&options.ICE.TURN, "turn", "", "TURN server URL, for example turn:127.0.0.1:3478?transport=udp")
	fs.StringVar(&options.ICE.TURNUsername, "turn-username", "", "TURN username")
	fs.StringVar(&options.ICE.TURNPassword, "turn-password", "", "TURN password")
	fs.BoolVar(&versionOnly, "version", false, "print version and exit")

	switch mode {
	case config.ModeExpose:
		fs.StringVar(&options.Target, "target", "", "local TCP target to expose, for example 127.0.0.1:22")
	case config.ModeConnect:
		fs.StringVar(&options.Listen, "listen", "127.0.0.1:2222", "local TCP listen address, for example 127.0.0.1:2222")
	}

	if err := fs.Parse(args); err != nil {
		return config.PeerOptions{}, false, err
	}

	var err error
	options.RendezvousToken, err = config.ResolveRendezvousToken(options.RendezvousToken)
	if err != nil {
		return config.PeerOptions{}, false, err
	}
	options.PairingSecret, err = config.ResolvePairingSecret(pairingSecret, pairingSecretFile, legacySecret, legacySecretFile)
	if err != nil {
		return config.PeerOptions{}, false, err
	}

	return options, versionOnly, nil
}

func (a *app) printVersion() {
	a.logger.Printf("rtc2tcp-peer version=%s commit=%s default-broker=%s", a.build.Version, a.build.Commit, a.build.DefaultBrokerURL)
}

// event emits a structured peer log line via logx.Event. Kept as a
// thin method so call sites read as `a.event("auth_failure", ...)`.
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

func (a *app) printRootUsage() {
	fmt.Fprintf(os.Stdout, "Usage:\n")
	fmt.Fprintf(os.Stdout, "  rtc2tcp-peer expose --rendezvous-token <token> --pairing-secret-file <path> --target <host:port> [flags]\n")
	fmt.Fprintf(os.Stdout, "  rtc2tcp-peer connect --rendezvous-token <token> --pairing-secret-file <path> [--listen 127.0.0.1:2222] [flags]\n\n")
	fmt.Fprintf(os.Stdout, "Environment: %s, %s, %s\n\n", config.EnvRendezvousToken, config.EnvPairingSecret, config.EnvPairingSecretFile)
	fmt.Fprintf(os.Stdout, "Flags are available per subcommand with --help.\n")
}
