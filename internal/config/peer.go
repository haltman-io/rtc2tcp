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

	switch o.Mode {
	case ModeExpose:
		if strings.TrimSpace(o.Target) == "" {
			return errors.New("target is required in expose mode")
		}
		if _, err := ValidateAddress(o.Target, AddressRoleTarget); err != nil {
			return fmt.Errorf("invalid target: %w", err)
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
