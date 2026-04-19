package webrtc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	psdp "github.com/pion/sdp/v3"
	pion "github.com/pion/webrtc/v4"

	"github.com/haltman-io/rtc2tcp/internal/auth"
	"github.com/haltman-io/rtc2tcp/internal/config"
	"github.com/haltman-io/rtc2tcp/internal/logx"
	"github.com/haltman-io/rtc2tcp/internal/signaling"
)

const controlChannelLabel = "rtc2tcp-auth"

var (
	ErrPreAuthPayloadChannel       = errors.New("payload datachannel opened before authentication")
	ErrUnexpectedAuthControlReplay = errors.New("unexpected replay-like auth control message")
	ErrUnexpectedInboundStream     = errors.New("unexpected inbound payload datachannel")
	ErrSessionClosed               = errors.New("session closed")
	ErrPeerConnectionFailed        = errors.New("peer connection failed")
	ErrPeerConnectionClosed        = errors.New("peer connection closed")
	ErrControlChannelClosed        = errors.New("control channel closed")
	errAuthMaterialNotReady        = errors.New("session binding material not ready")
)

type Config struct {
	Logger        *log.Logger
	Mode          config.PeerMode
	SessionID     string
	Initiator     bool
	ICE           config.ICEConfig
	Authenticator auth.Authenticator
	StateMachine  *StateMachine
	OnSignal      func(signaling.Signal)
	OnStream      func(*pion.DataChannel)
}

type Session struct {
	logger        *log.Logger
	mode          config.PeerMode
	sessionID     string
	authenticator auth.Authenticator
	stateMachine  *StateMachine
	onSignal      func(signaling.Signal)
	onStream      func(*pion.DataChannel)

	pc *pion.PeerConnection

	mu                sync.Mutex
	control           *pion.DataChannel
	controlOpen       bool
	localFingerprint  string
	remoteFingerprint string
	remoteDescription bool
	pendingCandidates []pion.ICECandidateInit
	authBound         bool
	authStarted       bool
	closeErr          error
	authenticated     bool
	authResult        error
	authReadyClosed   bool

	authReady chan struct{}
	closeOnce sync.Once
}

func NewSession(cfg Config) (*Session, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.Authenticator == nil {
		return nil, errors.New("authenticator is required")
	}
	if cfg.StateMachine == nil {
		return nil, errors.New("state machine is required")
	}
	if cfg.StateMachine.State() != StateSignaling {
		return nil, fmt.Errorf("new session requires %s state, got %s", StateSignaling, cfg.StateMachine.State())
	}
	if strings.TrimSpace(cfg.SessionID) == "" {
		return nil, errors.New("session ID is required")
	}

	pc, err := pion.NewPeerConnection(pion.Configuration{
		ICEServers: iceServers(cfg.ICE),
	})
	if err != nil {
		return nil, fmt.Errorf("create peer connection: %w", err)
	}

	s := &Session{
		logger:        cfg.Logger,
		mode:          cfg.Mode,
		sessionID:     cfg.SessionID,
		authenticator: cfg.Authenticator,
		stateMachine:  cfg.StateMachine,
		onSignal:      cfg.OnSignal,
		onStream:      cfg.OnStream,
		pc:            pc,
		authReady:     make(chan struct{}),
	}

	pc.OnICECandidate(func(candidate *pion.ICECandidate) {
		if candidate == nil || s.onSignal == nil {
			return
		}
		payload := candidate.ToJSON()
		s.onSignal(signaling.Signal{
			Kind: signaling.SignalKindICE,
			Candidate: &signaling.ICECandidatePayload{
				Candidate:        payload.Candidate,
				SDPMid:           payload.SDPMid,
				SDPMLineIndex:    payload.SDPMLineIndex,
				UsernameFragment: payload.UsernameFragment,
			},
		})
	})

	pc.OnConnectionStateChange(func(state pion.PeerConnectionState) {
		s.logger.Print(logx.Event("peer", "pc_state", "session_id", s.sessionID, "state", state.String()))
		if s.stateMachine.IsOneOf(StateClosing, StateClosed, StateFailed) {
			return
		}
		switch state {
		case pion.PeerConnectionStateFailed:
			s.fail(ErrPeerConnectionFailed)
		case pion.PeerConnectionStateClosed:
			s.fail(ErrPeerConnectionClosed)
		}
	})

	pc.OnDataChannel(func(dc *pion.DataChannel) {
		if dc.Label() == controlChannelLabel {
			s.attachControlChannel(dc)
			return
		}

		if err := s.prepareInboundPayloadChannel(); err != nil {
			_ = dc.Close()
			s.fail(err)
			return
		}

		if s.onStream == nil {
			_ = dc.Close()
			s.fail(ErrUnexpectedInboundStream)
			return
		}

		s.onStream(dc)
	})

	if cfg.Initiator {
		dc, err := pc.CreateDataChannel(controlChannelLabel, nil)
		if err != nil {
			_ = pc.Close()
			return nil, fmt.Errorf("create control channel: %w", err)
		}
		s.attachControlChannel(dc)
	}

	return s, nil
}

func (s *Session) CreateOffer(_ context.Context) (string, error) {
	offer, err := s.pc.CreateOffer(nil)
	if err != nil {
		return "", fmt.Errorf("create offer: %w", err)
	}
	if err := s.setLocalDescription(offer); err != nil {
		return "", err
	}
	return offer.SDP, nil
}

func (s *Session) HandleOffer(_ context.Context, offer string) (string, error) {
	if err := s.setRemoteDescription(pion.SessionDescription{
		Type: pion.SDPTypeOffer,
		SDP:  offer,
	}); err != nil {
		return "", err
	}

	answer, err := s.pc.CreateAnswer(nil)
	if err != nil {
		return "", fmt.Errorf("create answer: %w", err)
	}
	if err := s.setLocalDescription(answer); err != nil {
		return "", err
	}
	return answer.SDP, nil
}

func (s *Session) HandleAnswer(_ context.Context, answer string) error {
	return s.setRemoteDescription(pion.SessionDescription{
		Type: pion.SDPTypeAnswer,
		SDP:  answer,
	})
}

func (s *Session) AddRemoteCandidate(candidate signaling.ICECandidatePayload) error {
	init := pion.ICECandidateInit{
		Candidate:        candidate.Candidate,
		SDPMid:           candidate.SDPMid,
		SDPMLineIndex:    candidate.SDPMLineIndex,
		UsernameFragment: candidate.UsernameFragment,
	}

	s.mu.Lock()
	if !s.remoteDescription {
		s.pendingCandidates = append(s.pendingCandidates, init)
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if err := s.pc.AddICECandidate(init); err != nil {
		return fmt.Errorf("add remote candidate: %w", err)
	}
	return nil
}

func (s *Session) OpenStreamChannel(label string) (*pion.DataChannel, error) {
	if !s.stateMachine.IsOneOf(StateAuthenticated, StateStreaming) || !s.IsAuthenticated() {
		return nil, errors.New("session is not authenticated yet")
	}

	dc, err := s.pc.CreateDataChannel(label, nil)
	if err != nil {
		return nil, err
	}
	if err := s.stateMachine.Transition(StateStreaming); err != nil {
		_ = dc.Close()
		return nil, err
	}
	return dc, nil
}

func (s *Session) WaitAuthenticated(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.authReady:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.authResult
	}
}

func (s *Session) IsAuthenticated() bool {
	select {
	case <-s.authReady:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.authResult == nil && s.authenticated
	default:
		return false
	}
}

func (s *Session) Fail(err error) error {
	s.fail(err)
	return err
}

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if !s.stateMachine.IsOneOf(StateClosed, StateFailed) {
			if err := s.stateMachine.Transition(StateClosing); err != nil && !s.stateMachine.IsOneOf(StateClosing) {
				s.logger.Print(logx.Event("peer", "state_transition_failed", "session_id", s.sessionID, "target", "CLOSING", "err", err.Error()))
			}
		}
		s.completeAuthResult(ErrSessionClosed, false)
		if err := s.pc.Close(); err != nil {
			s.mu.Lock()
			s.closeErr = err
			s.mu.Unlock()
			return
		}
		if s.stateMachine.IsOneOf(StateClosing) {
			if err := s.stateMachine.Transition(StateClosed); err != nil {
				s.logger.Print(logx.Event("peer", "state_transition_failed", "session_id", s.sessionID, "target", "CLOSED", "err", err.Error()))
			}
		}
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

func (s *Session) attachControlChannel(dc *pion.DataChannel) {
	s.mu.Lock()
	if s.control != nil && s.control != dc {
		s.mu.Unlock()
		_ = dc.Close()
		s.fail(ErrUnexpectedAuthControlReplay)
		return
	}
	s.control = dc
	s.mu.Unlock()

	dc.OnOpen(func() {
		s.logger.Print(logx.Event("peer", "control_channel_open", "session_id", s.sessionID))
		s.mu.Lock()
		s.controlOpen = true
		s.mu.Unlock()
		s.maybeSendAuth()
	})

	dc.OnMessage(func(message pion.DataChannelMessage) {
		if err := s.handleControlMessage(message.Data); err != nil {
			s.fail(err)
		}
	})

	dc.OnClose(func() {
		if s.stateMachine.IsOneOf(StateClosing, StateClosed, StateFailed) {
			return
		}
		s.fail(ErrControlChannelClosed)
	})
}

func (s *Session) handleControlMessage(data []byte) error {
	if !s.stateMachine.IsOneOf(StateAuthPending) {
		return ErrUnexpectedAuthControlReplay
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var inbound auth.Message
	if err := decoder.Decode(&inbound); err != nil {
		return fmt.Errorf("decode auth message: %w", err)
	}

	control, err := s.bindAuthenticator()
	if err != nil {
		return err
	}

	outbound, hasOutbound, done, err := s.authenticator.Step(inbound)
	if err != nil {
		return err
	}
	if hasOutbound {
		if err := sendAuthMessage(control, outbound); err != nil {
			return err
		}
	}
	if done {
		if err := s.stateMachine.Transition(StateAuthenticated); err != nil {
			return err
		}
		s.completeAuthResult(nil, true)
		s.logger.Print(logx.Event("peer", "auth_succeeded", "session_id", s.sessionID, "scheme", s.authenticator.Name()))
	}
	return nil
}

func (s *Session) maybeSendAuth() {
	if !s.stateMachine.IsOneOf(StateAuthPending) {
		return
	}

	s.mu.Lock()
	if !s.controlOpen {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	control, err := s.bindAuthenticator()
	if err != nil {
		if errors.Is(err, errAuthMaterialNotReady) {
			return
		}
		s.fail(err)
		return
	}

	s.mu.Lock()
	if s.mode != config.ModeConnect || s.authStarted {
		s.mu.Unlock()
		return
	}
	s.authStarted = true
	s.mu.Unlock()

	hello, err := s.authenticator.Start()
	if err != nil {
		s.fail(err)
		return
	}
	if err := sendAuthMessage(control, hello); err != nil {
		s.fail(err)
		return
	}
}

// bindAuthenticator ensures the authenticator is bound to the current
// session material and returns the control channel for write. It is safe
// to call from both the initiator's start path and the responder's
// inbound path; Bind is idempotent per session.
func (s *Session) bindAuthenticator() (*pion.DataChannel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	control := s.control
	if control == nil {
		return nil, errors.New("control channel is not attached")
	}
	if s.authBound {
		return control, nil
	}
	material, err := s.materialLocked()
	if err != nil {
		return nil, err
	}
	if err := s.authenticator.Bind(material); err != nil {
		return nil, err
	}
	s.authBound = true
	return control, nil
}

func sendAuthMessage(control *pion.DataChannel, msg auth.Message) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode auth message: %w", err)
	}
	if err := control.SendText(string(payload)); err != nil {
		return fmt.Errorf("send auth message: %w", err)
	}
	return nil
}

func (s *Session) materialLocked() (auth.SessionBindingMaterial, error) {
	if s.localFingerprint == "" || s.remoteFingerprint == "" {
		return auth.SessionBindingMaterial{}, errAuthMaterialNotReady
	}
	return auth.SessionBindingMaterial{
		SessionID:         s.sessionID,
		Mode:              s.mode,
		LocalFingerprint:  s.localFingerprint,
		RemoteFingerprint: s.remoteFingerprint,
	}, nil
}

func (s *Session) setLocalDescription(desc pion.SessionDescription) error {
	if err := s.pc.SetLocalDescription(desc); err != nil {
		return fmt.Errorf("set local description: %w", err)
	}

	local := s.pc.LocalDescription()
	if local == nil {
		return errors.New("local description not available")
	}

	fingerprint, err := ExtractTransportFingerprint(local.SDP)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.localFingerprint = fingerprint
	s.mu.Unlock()
	s.maybeEnterAuthPending()
	return nil
}

func (s *Session) setRemoteDescription(desc pion.SessionDescription) error {
	if err := s.pc.SetRemoteDescription(desc); err != nil {
		return fmt.Errorf("set remote description: %w", err)
	}

	fingerprint, err := ExtractTransportFingerprint(desc.SDP)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.remoteFingerprint = fingerprint
	s.remoteDescription = true
	pending := append([]pion.ICECandidateInit(nil), s.pendingCandidates...)
	s.pendingCandidates = nil
	s.mu.Unlock()

	for _, candidate := range pending {
		if err := s.pc.AddICECandidate(candidate); err != nil {
			return fmt.Errorf("flush remote candidate: %w", err)
		}
	}

	s.maybeEnterAuthPending()
	return nil
}

func (s *Session) maybeEnterAuthPending() {
	s.mu.Lock()
	ready := s.localFingerprint != "" && s.remoteFingerprint != ""
	s.mu.Unlock()
	if !ready {
		return
	}
	if s.stateMachine.IsOneOf(StateSignaling) {
		if err := s.stateMachine.Transition(StateAuthPending); err != nil {
			s.fail(err)
			return
		}
	}
	s.maybeSendAuth()
}

func (s *Session) prepareInboundPayloadChannel() error {
	if !s.stateMachine.IsOneOf(StateAuthenticated, StateStreaming) || !s.IsAuthenticated() {
		return ErrPreAuthPayloadChannel
	}
	if err := s.stateMachine.Transition(StateStreaming); err != nil {
		return err
	}
	return nil
}

func (s *Session) fail(err error) {
	if err == nil {
		err = errors.New("unknown session error")
	}

	s.completeAuthResult(err, false)
	s.closeOnce.Do(func() {
		if !s.stateMachine.IsOneOf(StateFailed, StateClosed) {
			if transitionErr := s.stateMachine.Transition(StateFailed); transitionErr != nil && !s.stateMachine.IsOneOf(StateFailed) {
				s.logger.Print(logx.Event("peer", "state_transition_failed", "session_id", s.sessionID, "target", "FAILED", "err", transitionErr.Error()))
			}
		}
		if closeErr := s.pc.Close(); closeErr != nil {
			s.mu.Lock()
			s.closeErr = closeErr
			s.mu.Unlock()
		}
	})
}

func (s *Session) completeAuthResult(err error, authenticated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.authReadyClosed {
		return
	}

	s.authenticated = authenticated
	s.authResult = err
	s.authReadyClosed = true
	close(s.authReady)
}

func ExtractTransportFingerprint(rawSDP string) (string, error) {
	var desc psdp.SessionDescription
	if err := desc.UnmarshalString(rawSDP); err != nil {
		return "", fmt.Errorf("parse SDP: %w", err)
	}

	sessionFingerprint := extractFingerprintAttribute(desc.Attributes)
	for _, media := range desc.MediaDescriptions {
		if media == nil || media.MediaName.Media != "application" {
			continue
		}
		if fingerprint := extractFingerprintAttribute(media.Attributes); fingerprint != "" {
			return strings.ToUpper(fingerprint), nil
		}
		if sessionFingerprint != "" {
			return strings.ToUpper(sessionFingerprint), nil
		}
		return "", errors.New("application media fingerprint not found")
	}

	if sessionFingerprint != "" {
		return strings.ToUpper(sessionFingerprint), nil
	}
	return "", errors.New("SDP fingerprint not found")
}

func extractFingerprintAttribute(attributes []psdp.Attribute) string {
	for _, attribute := range attributes {
		if attribute.Key != "fingerprint" {
			continue
		}
		return strings.TrimSpace(attribute.Value)
	}
	return ""
}

func iceServers(ice config.ICEConfig) []pion.ICEServer {
	var servers []pion.ICEServer

	if ice.STUN != "" {
		servers = append(servers, pion.ICEServer{
			URLs: []string{ice.STUN},
		})
	}

	if ice.TURN != "" {
		servers = append(servers, pion.ICEServer{
			URLs:       []string{ice.TURN},
			Username:   ice.TURNUsername,
			Credential: ice.TURNPassword,
		})
	}

	return servers
}
