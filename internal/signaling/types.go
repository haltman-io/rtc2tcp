package signaling

type Message struct {
	Type       string        `json:"type"`
	Register   *Register     `json:"register,omitempty"`
	Paired     *Paired       `json:"paired,omitempty"`
	Signal     *Signal       `json:"signal,omitempty"`
	Error      *ErrorPayload `json:"error,omitempty"`
	PeerLeft   *PeerLeft     `json:"peerLeft,omitempty"`
	Registered *Registered   `json:"registered,omitempty"`
}

type Register struct {
	RendezvousToken string `json:"rendezvousToken"`
	Mode            string `json:"mode"`
	Version         string `json:"version,omitempty"`
}

type Registered struct {
	PeerID string `json:"peerID"`
}

type Paired struct {
	SessionID string `json:"sessionID"`
	Initiator bool   `json:"initiator"`
	PeerMode  string `json:"peerMode"`
}

type Signal struct {
	Kind      string               `json:"kind"`
	SDP       *SDPPayload          `json:"sdp,omitempty"`
	Candidate *ICECandidatePayload `json:"candidate,omitempty"`
}

type SDPPayload struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type ICECandidatePayload struct {
	Candidate        string  `json:"candidate"`
	SDPMid           *string `json:"sdpMid,omitempty"`
	SDPMLineIndex    *uint16 `json:"sdpMLineIndex,omitempty"`
	UsernameFragment *string `json:"usernameFragment,omitempty"`
}

type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type PeerLeft struct {
	Reason string `json:"reason,omitempty"`
}

const (
	MessageTypeRegister   = "register"
	MessageTypeRegistered = "registered"
	MessageTypePaired     = "paired"
	MessageTypeSignal     = "signal"
	MessageTypeError      = "error"
	MessageTypePeerLeft   = "peer-left"

	SignalKindOffer  = "offer"
	SignalKindAnswer = "answer"
	SignalKindICE    = "ice-candidate"
)
