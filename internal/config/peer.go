package config

import (
	"errors"
	"fmt"
	"strings"
)

type PeerMode string

const (
	ModeExpose  PeerMode = "expose"
	ModeConnect PeerMode = "connect"
)

func (m PeerMode) String() string {
	return string(m)
}

func ParsePeerMode(value string) (PeerMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(ModeExpose):
		return ModeExpose, nil
	case string(ModeConnect):
		return ModeConnect, nil
	default:
		return "", fmt.Errorf("unsupported mode %q", value)
	}
}

func (m PeerMode) Peer() PeerMode {
	switch m {
	case ModeExpose:
		return ModeConnect
	case ModeConnect:
		return ModeExpose
	default:
		return ""
	}
}

type ICEConfig struct {
	STUN         string
	TURN         string
	TURNUsername string
	TURNPassword string
}

type PeerOptions struct {
	Mode            PeerMode
	RendezvousToken string
	PairingSecret   string
	BrokerURL       string
	ICE             ICEConfig
	Target          string
	Listen          string
	/* SOCKS5 switches the tunnel into SOCKS5 proxy mode. On the expose side
	the target is resolved per-stream from the connect peer's channel label
	instead of a fixed --target flag. On the connect side the --listen
	address accepts SOCKS5 CONNECT requests (RFC 1928), so any TCP client
	that speaks SOCKS5 can route traffic without a separate tunnel per host. */
	SOCKS5 bool
	/* HTTPConnect switches the tunnel into HTTP CONNECT proxy mode. On the
	expose side the target is resolved per-stream from the connect peer's
	channel label. On the connect side the --listen address accepts HTTP
	CONNECT requests (RFC 7231 §4.3.6), so browsers and HTTP clients that
	support CONNECT proxies can route traffic through the tunnel. */
	HTTPConnect bool
}

func (o PeerOptions) Validate() error {
	if strings.TrimSpace(o.RendezvousToken) == "" {
		return errors.New("rendezvous token is required")
	}
	if strings.TrimSpace(o.PairingSecret) == "" {
		return errors.New("pairing secret is required")
	}
	if strings.TrimSpace(o.BrokerURL) == "" {
		return errors.New("broker URL is required")
	}

	if o.SOCKS5 && o.HTTPConnect {
		return errors.New("--socks5 and --http-connect are mutually exclusive")
	}

	switch o.Mode {
	case ModeExpose:
		if !o.SOCKS5 && !o.HTTPConnect {
			if strings.TrimSpace(o.Target) == "" {
				return errors.New("target is required in expose mode (or use --socks5 / --http-connect)")
			}
			if _, err := ValidateAddress(o.Target, AddressRoleTarget); err != nil {
				return fmt.Errorf("invalid target: %w", err)
			}
		}
	case ModeConnect:
		if strings.TrimSpace(o.Listen) == "" {
			return errors.New("listen is required in connect mode")
		}
		if _, err := ValidateAddress(o.Listen, AddressRoleListen); err != nil {
			return fmt.Errorf("invalid listen: %w", err)
		}
	default:
		return fmt.Errorf("unsupported mode %q", o.Mode)
	}

	return nil
}
