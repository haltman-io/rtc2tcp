package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/group"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/haltman-io/rtc2tcp/internal/config"
)

// Milestone 2 interactive peer-authentication subsystem.
//
// The wire format, transcript shape, key schedule, and state machine are
// specified in PROTOCOL.md, section "Milestone 2 Authentication".
//
// The PAKE primitive is selected at construction time. The default is
// SchemeCPACEV2 (CPACE over Ristretto255 via github.com/cloudflare/circl).
// SchemeTransitionalV2 remains implemented for backward compatibility;
// the scheme-pin check in Step blocks a CPACE-configured peer from
// accepting a transitional counterparty, which is the downgrade-
// prevention guarantee.

const (
	// SchemeCPACEV2 is the Milestone 2 CPACE-Ristretto255 scheme.
	SchemeCPACEV2 = "rtc2tcp-auth/cpace-ristretto255-v2"

	// SchemeTransitionalV2 is the transitional ECDH scheme. It is not a
	// PAKE. Retained for rollout only.
	SchemeTransitionalV2 = "rtc2tcp-auth/interactive-ecdh-v2a"

	cpaceGeneratorDST = "rtc2tcp-auth/cpace-gen/v2"

	scalarLen = 32
	pointLen  = 32
	macLen    = 32
)

var (
	ErrPeerAuthFailed           = errors.New("peer authentication failed")
	ErrAuthStateOutOfOrder      = errors.New("auth state machine out of order")
	ErrAuthSchemeMismatch       = errors.New("auth scheme mismatch")
	ErrAuthRoleMismatch         = errors.New("auth role mismatch")
	ErrAuthInvalidShare         = errors.New("auth share is invalid")
	ErrAuthConfirmationMismatch = errors.New("auth confirmation mismatch")
	ErrAuthUnbound              = errors.New("authenticator has not been bound to session material")
	ErrAuthUnexpectedKind       = errors.New("unexpected auth message kind")
	ErrAuthNotComplete          = errors.New("authentication is not complete")
	ErrAuthUnsupportedScheme    = errors.New("unsupported auth scheme")
)

// SessionBindingMaterial binds the interactive authenticator to a concrete
// WebRTC session. Fingerprints are the DataChannel-transport DTLS
// fingerprints selected by ExtractTransportFingerprint (application
// m-section). All fields are required.
type SessionBindingMaterial struct {
	SessionID         string
	Mode              config.PeerMode
	LocalFingerprint  string
	RemoteFingerprint string
}

type (
	BindingMaterial = SessionBindingMaterial
	Material        = SessionBindingMaterial
)

// MessageKind tags a control-channel auth message.
type MessageKind string

const (
	MessageKindHello   MessageKind = "hello"
	MessageKindAccept  MessageKind = "accept"
	MessageKindConfirm MessageKind = "confirm"
)

// Message is the wire format for every control-channel auth message.
// See PROTOCOL.md, "Milestone 2 Authentication / Wire Format".
type Message struct {
	Scheme        string      `json:"scheme"`
	Kind          MessageKind `json:"kind"`
	InitiatorRole string      `json:"initiator_role,omitempty"`
	ResponderRole string      `json:"responder_role,omitempty"`
	Share         string      `json:"share,omitempty"`
	Confirmation  string      `json:"confirmation,omitempty"`
}

// AuthState is the authenticator's internal state machine. See PROTOCOL.md
// for the per-role transition diagram.
type AuthState string

const (
	AuthStateInit        AuthState = "INIT"
	AuthStateSentHello   AuthState = "SENT_HELLO"
	AuthStateSentAccept  AuthState = "SENT_ACCEPT"
	AuthStateSentConfirm AuthState = "SENT_CONFIRM"
	AuthStateSucceeded   AuthState = "SUCCEEDED"
	AuthStateFailed      AuthState = "FAILED"
)

// Authenticator drives the interactive control-channel authentication
// handshake. Implementations are single-use: once State() returns
// SUCCEEDED or FAILED, further input must be rejected.
type Authenticator interface {
	Name() string
	State() AuthState
	Bind(SessionBindingMaterial) error
	Start() (Message, error)
	Step(Message) (outbound Message, hasOutbound bool, done bool, err error)
	SessionKey() ([]byte, error)
}

// InteractiveAuthenticator implements the Milestone 2 flow from
// PROTOCOL.md. The PAKE primitive is chosen at construction time via the
// scheme identifier; the wire format, transcript, key schedule, and
// state machine are identical across schemes.
type InteractiveAuthenticator struct {
	pairingSecret []byte
	scheme        string
	state         AuthState
	rng           io.Reader

	bound     bool
	initiator bool
	material  SessionBindingMaterial

	// Transitional ECDH scheme state.
	priv [scalarLen]byte
	pub  [pointLen]byte

	// CPACE-Ristretto255 scheme state.
	cpaceScalar    group.Scalar
	cpaceGenerator group.Element
	cpaceLocal     group.Element
	cpaceShare     [pointLen]byte

	peerShare        [pointLen]byte
	havePeerShare    bool
	transcript       []byte
	sessionKey       []byte
	initiatorConfirm []byte
	responderConfirm []byte
}

// NewInteractiveAuthenticator constructs the default Milestone 2
// authenticator (CPACE-Ristretto255).
func NewInteractiveAuthenticator(pairingSecret string) (*InteractiveAuthenticator, error) {
	return NewInteractiveAuthenticatorWithScheme(pairingSecret, SchemeCPACEV2)
}

// NewInteractiveAuthenticatorWithScheme constructs an authenticator for a
// specific scheme. Use this only for tests or controlled rollout; the
// default construction above is the production choice.
func NewInteractiveAuthenticatorWithScheme(pairingSecret, scheme string) (*InteractiveAuthenticator, error) {
	return newInteractiveAuthenticator(pairingSecret, scheme, rand.Reader)
}

func newInteractiveAuthenticator(pairingSecret, scheme string, rng io.Reader) (*InteractiveAuthenticator, error) {
	trimmed := strings.TrimSpace(pairingSecret)
	if trimmed == "" {
		return nil, errors.New("pairing secret is required")
	}
	switch scheme {
	case SchemeCPACEV2, SchemeTransitionalV2:
	default:
		return nil, fmt.Errorf("%w: %q", ErrAuthUnsupportedScheme, scheme)
	}
	if rng == nil {
		rng = rand.Reader
	}
	return &InteractiveAuthenticator{
		pairingSecret: []byte(trimmed),
		scheme:        scheme,
		state:         AuthStateInit,
		rng:           rng,
	}, nil
}

func (a *InteractiveAuthenticator) Name() string     { return a.scheme }
func (a *InteractiveAuthenticator) State() AuthState { return a.state }

func (a *InteractiveAuthenticator) Bind(material SessionBindingMaterial) error {
	if a.state != AuthStateInit {
		return ErrAuthStateOutOfOrder
	}
	if err := validateMaterial(material); err != nil {
		return err
	}
	a.material = SessionBindingMaterial{
		SessionID:         strings.TrimSpace(material.SessionID),
		Mode:              material.Mode,
		LocalFingerprint:  canonicalFingerprint(material.LocalFingerprint),
		RemoteFingerprint: canonicalFingerprint(material.RemoteFingerprint),
	}
	a.initiator = material.Mode == config.ModeConnect

	switch a.scheme {
	case SchemeCPACEV2:
		if err := a.setupCPACE(); err != nil {
			return err
		}
	case SchemeTransitionalV2:
		if err := a.setupECDH(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: %q", ErrAuthUnsupportedScheme, a.scheme)
	}

	a.bound = true
	return nil
}

func (a *InteractiveAuthenticator) setupECDH() error {
	if _, err := io.ReadFull(a.rng, a.priv[:]); err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}
	pub, err := curve25519.X25519(a.priv[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("derive public share: %w", err)
	}
	if len(pub) != pointLen {
		return fmt.Errorf("unexpected share length %d", len(pub))
	}
	copy(a.pub[:], pub)
	return nil
}

func (a *InteractiveAuthenticator) setupCPACE() error {
	initiatorFP, responderFP := a.orderedFingerprints()

	var msg bytes.Buffer
	writeLenPrefixed(&msg, a.pairingSecret)
	writeLenPrefixed(&msg, []byte(a.material.SessionID))
	writeLenPrefixed(&msg, []byte(initiatorFP))
	writeLenPrefixed(&msg, []byte(responderFP))

	a.cpaceGenerator = group.Ristretto255.HashToElement(msg.Bytes(), []byte(cpaceGeneratorDST))
	if a.cpaceGenerator.IsIdentity() {
		return errors.New("cpace generator is identity")
	}

	a.cpaceScalar = group.Ristretto255.RandomNonZeroScalar(a.rng)

	a.cpaceLocal = group.Ristretto255.NewElement()
	a.cpaceLocal.Mul(a.cpaceGenerator, a.cpaceScalar)
	if a.cpaceLocal.IsIdentity() {
		return errors.New("cpace local share is identity")
	}

	shareBytes, err := a.cpaceLocal.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal cpace share: %w", err)
	}
	if len(shareBytes) != pointLen {
		return fmt.Errorf("unexpected cpace share length %d", len(shareBytes))
	}
	copy(a.cpaceShare[:], shareBytes)
	return nil
}

func (a *InteractiveAuthenticator) localShareBytes() [pointLen]byte {
	if a.scheme == SchemeCPACEV2 {
		return a.cpaceShare
	}
	return a.pub
}

func (a *InteractiveAuthenticator) Start() (Message, error) {
	if !a.bound {
		return Message{}, ErrAuthUnbound
	}
	if !a.initiator {
		return Message{}, ErrAuthStateOutOfOrder
	}
	if a.state != AuthStateInit {
		return Message{}, ErrAuthStateOutOfOrder
	}
	share := a.localShareBytes()
	msg := Message{
		Scheme:        a.scheme,
		Kind:          MessageKindHello,
		InitiatorRole: config.ModeConnect.String(),
		ResponderRole: config.ModeExpose.String(),
		Share:         base64.RawURLEncoding.EncodeToString(share[:]),
	}
	a.state = AuthStateSentHello
	return msg, nil
}

func (a *InteractiveAuthenticator) Step(inbound Message) (Message, bool, bool, error) {
	if !a.bound {
		return Message{}, false, false, ErrAuthUnbound
	}
	if a.state == AuthStateSucceeded || a.state == AuthStateFailed {
		return Message{}, false, false, ErrAuthStateOutOfOrder
	}
	if inbound.Scheme != a.scheme {
		a.fail()
		return Message{}, false, false, fmt.Errorf("%w: got %q want %q", ErrAuthSchemeMismatch, inbound.Scheme, a.scheme)
	}
	if a.initiator {
		return a.stepInitiator(inbound)
	}
	return a.stepResponder(inbound)
}

func (a *InteractiveAuthenticator) stepResponder(inbound Message) (Message, bool, bool, error) {
	switch a.state {
	case AuthStateInit:
		if inbound.Kind != MessageKindHello {
			a.fail()
			return Message{}, false, false, fmt.Errorf("%w: expected hello, got %q", ErrAuthUnexpectedKind, inbound.Kind)
		}
		if inbound.InitiatorRole != config.ModeConnect.String() || inbound.ResponderRole != config.ModeExpose.String() {
			a.fail()
			return Message{}, false, false, ErrAuthRoleMismatch
		}
		if err := a.consumePeerShare(inbound.Share); err != nil {
			a.fail()
			return Message{}, false, false, err
		}
		if err := a.computeTranscriptAndKeys(); err != nil {
			a.fail()
			return Message{}, false, false, err
		}
		share := a.localShareBytes()
		out := Message{
			Scheme:       a.scheme,
			Kind:         MessageKindAccept,
			Share:        base64.RawURLEncoding.EncodeToString(share[:]),
			Confirmation: base64.RawURLEncoding.EncodeToString(a.responderConfirm),
		}
		a.state = AuthStateSentAccept
		return out, true, false, nil

	case AuthStateSentAccept:
		if inbound.Kind != MessageKindConfirm {
			a.fail()
			return Message{}, false, false, fmt.Errorf("%w: expected confirm, got %q", ErrAuthUnexpectedKind, inbound.Kind)
		}
		if err := a.verifyInitiatorConfirm(inbound.Confirmation); err != nil {
			a.fail()
			return Message{}, false, false, err
		}
		a.state = AuthStateSucceeded
		return Message{}, false, true, nil

	default:
		a.fail()
		return Message{}, false, false, ErrAuthStateOutOfOrder
	}
}

func (a *InteractiveAuthenticator) stepInitiator(inbound Message) (Message, bool, bool, error) {
	if a.state != AuthStateSentHello {
		a.fail()
		return Message{}, false, false, ErrAuthStateOutOfOrder
	}
	if inbound.Kind != MessageKindAccept {
		a.fail()
		return Message{}, false, false, fmt.Errorf("%w: expected accept, got %q", ErrAuthUnexpectedKind, inbound.Kind)
	}
	if err := a.consumePeerShare(inbound.Share); err != nil {
		a.fail()
		return Message{}, false, false, err
	}
	if err := a.computeTranscriptAndKeys(); err != nil {
		a.fail()
		return Message{}, false, false, err
	}
	if err := a.verifyResponderConfirm(inbound.Confirmation); err != nil {
		a.fail()
		return Message{}, false, false, err
	}
	out := Message{
		Scheme:       a.scheme,
		Kind:         MessageKindConfirm,
		Confirmation: base64.RawURLEncoding.EncodeToString(a.initiatorConfirm),
	}
	a.state = AuthStateSucceeded
	return out, true, true, nil
}

func (a *InteractiveAuthenticator) SessionKey() ([]byte, error) {
	if a.state != AuthStateSucceeded {
		return nil, ErrAuthNotComplete
	}
	return append([]byte(nil), a.sessionKey...), nil
}

func (a *InteractiveAuthenticator) fail() { a.state = AuthStateFailed }

func (a *InteractiveAuthenticator) consumePeerShare(encoded string) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != pointLen {
		return ErrAuthInvalidShare
	}
	var zero [pointLen]byte
	if subtle.ConstantTimeCompare(raw, zero[:]) == 1 {
		return ErrAuthInvalidShare
	}
	copy(a.peerShare[:], raw)
	a.havePeerShare = true
	return nil
}

func (a *InteractiveAuthenticator) computeTranscriptAndKeys() error {
	if !a.havePeerShare {
		return ErrAuthInvalidShare
	}

	pakeShared, err := a.derivePakeShared()
	if err != nil {
		return err
	}

	var initiatorShare, responderShare [pointLen]byte
	var initiatorFingerprint, responderFingerprint string
	localShare := a.localShareBytes()
	if a.initiator {
		initiatorShare = localShare
		responderShare = a.peerShare
		initiatorFingerprint = a.material.LocalFingerprint
		responderFingerprint = a.material.RemoteFingerprint
	} else {
		initiatorShare = a.peerShare
		responderShare = localShare
		initiatorFingerprint = a.material.RemoteFingerprint
		responderFingerprint = a.material.LocalFingerprint
	}

	transcript := buildTranscript(
		a.scheme,
		a.material.SessionID,
		config.ModeConnect.String(),
		config.ModeExpose.String(),
		initiatorFingerprint,
		responderFingerprint,
		initiatorShare[:],
		responderShare[:],
	)

	pairingMix := argon2.IDKey(
		a.pairingSecret,
		pairingSalt(a.material.SessionID),
		1,
		8*1024,
		1,
		32,
	)
	ikm := make([]byte, 0, len(pakeShared)+len(pairingMix))
	ikm = append(ikm, pakeShared...)
	ikm = append(ikm, pairingMix...)

	prk := hkdfExtract(transcript, ikm)
	a.transcript = transcript
	a.sessionKey = hkdfExpand(prk, []byte("rtc2tcp/m2/session-key/v1"), 32)
	kInit := hkdfExpand(prk, []byte("rtc2tcp/m2/confirm-key/initiator/v1"), 32)
	kResp := hkdfExpand(prk, []byte("rtc2tcp/m2/confirm-key/responder/v1"), 32)
	a.initiatorConfirm = macTranscript(kInit, transcript)
	a.responderConfirm = macTranscript(kResp, transcript)
	return nil
}

// derivePakeShared is the PAKE primitive dispatcher. CPACE-Ristretto255
// is the default; the transitional ECDH branch is retained for rollout.
func (a *InteractiveAuthenticator) derivePakeShared() ([]byte, error) {
	switch a.scheme {
	case SchemeCPACEV2:
		return a.derivePakeSharedCPACE()
	case SchemeTransitionalV2:
		return a.derivePakeSharedECDH()
	default:
		return nil, fmt.Errorf("%w: %q", ErrAuthUnsupportedScheme, a.scheme)
	}
}

func (a *InteractiveAuthenticator) derivePakeSharedCPACE() ([]byte, error) {
	peerElement := group.Ristretto255.NewElement()
	if err := peerElement.UnmarshalBinary(a.peerShare[:]); err != nil {
		return nil, ErrAuthInvalidShare
	}
	if peerElement.IsIdentity() {
		return nil, ErrAuthInvalidShare
	}
	result := group.Ristretto255.NewElement()
	result.Mul(peerElement, a.cpaceScalar)
	if result.IsIdentity() {
		return nil, ErrAuthInvalidShare
	}
	out, err := result.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal cpace shared: %w", err)
	}
	return out, nil
}

func (a *InteractiveAuthenticator) derivePakeSharedECDH() ([]byte, error) {
	shared, err := curve25519.X25519(a.priv[:], a.peerShare[:])
	if err != nil {
		return nil, ErrAuthInvalidShare
	}
	var zero [pointLen]byte
	if subtle.ConstantTimeCompare(shared, zero[:]) == 1 {
		return nil, ErrAuthInvalidShare
	}
	return shared, nil
}

func (a *InteractiveAuthenticator) orderedFingerprints() (string, string) {
	if a.initiator {
		return a.material.LocalFingerprint, a.material.RemoteFingerprint
	}
	return a.material.RemoteFingerprint, a.material.LocalFingerprint
}

func (a *InteractiveAuthenticator) verifyResponderConfirm(encoded string) error {
	return verifyConfirmation(encoded, a.responderConfirm)
}

func (a *InteractiveAuthenticator) verifyInitiatorConfirm(encoded string) error {
	return verifyConfirmation(encoded, a.initiatorConfirm)
}

func verifyConfirmation(encoded string, expected []byte) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != macLen {
		return fmt.Errorf("%w: %w", ErrPeerAuthFailed, ErrAuthConfirmationMismatch)
	}
	if subtle.ConstantTimeCompare(raw, expected) != 1 {
		return fmt.Errorf("%w: %w", ErrPeerAuthFailed, ErrAuthConfirmationMismatch)
	}
	return nil
}

func buildTranscript(
	scheme, sessionID, initiatorRole, responderRole, initiatorFingerprint, responderFingerprint string,
	initiatorShare, responderShare []byte,
) []byte {
	h := sha256.New()
	writeLenPrefixed(h, []byte("rtc2tcp-auth/transcript/v2"))
	writeLenPrefixed(h, []byte(scheme))
	writeLenPrefixed(h, []byte(sessionID))
	writeLenPrefixed(h, []byte(initiatorRole))
	writeLenPrefixed(h, []byte(responderRole))
	writeLenPrefixed(h, []byte(initiatorFingerprint))
	writeLenPrefixed(h, []byte(responderFingerprint))
	writeLenPrefixed(h, initiatorShare)
	writeLenPrefixed(h, responderShare)
	return h.Sum(nil)
}

func writeLenPrefixed(w io.Writer, b []byte) {
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(b)))
	_, _ = w.Write(lenBytes[:])
	_, _ = w.Write(b)
}

func pairingSalt(sessionID string) []byte {
	h := sha256.New()
	h.Write([]byte("rtc2tcp/m2/pairing-salt/v1"))
	h.Write([]byte(sessionID))
	return h.Sum(nil)
}

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	r := hkdf.Expand(sha256.New, prk, info)
	out := make([]byte, length)
	_, _ = io.ReadFull(r, out)
	return out
}

func macTranscript(key, transcript []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(transcript)
	return m.Sum(nil)
}

func canonicalFingerprint(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func validateMaterial(m SessionBindingMaterial) error {
	if strings.TrimSpace(m.SessionID) == "" {
		return errors.New("session ID is required")
	}
	if strings.TrimSpace(m.LocalFingerprint) == "" {
		return errors.New("local fingerprint is required")
	}
	if strings.TrimSpace(m.RemoteFingerprint) == "" {
		return errors.New("remote fingerprint is required")
	}
	switch m.Mode {
	case config.ModeConnect, config.ModeExpose:
		return nil
	default:
		return fmt.Errorf("unsupported mode %q", m.Mode)
	}
}
