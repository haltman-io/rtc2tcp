package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ConnectionScheme is the URL scheme for the shareable rtc2tcp peer
// connection string: rtc2tcp://TOKEN:SECRET@HOST[:PORT][/PATH].
const ConnectionScheme = "rtc2tcp"

// ConnectionString bundles everything a connect peer needs to reach
// and authenticate with its expose counterpart.
type ConnectionString struct {
	RendezvousToken string
	PairingSecret   string
	BrokerURL       string
}

// ParseConnectionString parses the compact form.
//
//	rtc2tcp://TOKEN:SECRET@HOST[:PORT][/PATH]
//
// All three fields are required; the broker URL is reconstructed from
// the host component. If the host is a loopback address the broker
// URL is prefixed with http://, otherwise https:// — the same policy
// the WebSocket client enforces on the --broker flag.
func ParseConnectionString(raw string) (*ConnectionString, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("connection string is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}
	if u.Scheme != ConnectionScheme {
		return nil, fmt.Errorf("connection string scheme must be %q, got %q", ConnectionScheme, u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("connection string is missing the broker host")
	}
	if u.User == nil {
		return nil, errors.New("connection string is missing the rendezvous token and pairing secret")
	}
	token, err := url.QueryUnescape(u.User.Username())
	if err != nil {
		return nil, fmt.Errorf("decode rendezvous token: %w", err)
	}
	if token == "" {
		return nil, errors.New("connection string is missing the rendezvous token")
	}
	rawSecret, hasSecret := u.User.Password()
	if !hasSecret || rawSecret == "" {
		return nil, errors.New("connection string is missing the pairing secret")
	}
	secret, err := url.QueryUnescape(rawSecret)
	if err != nil {
		return nil, fmt.Errorf("decode pairing secret: %w", err)
	}

	scheme := "https"
	if isLoopbackHost(u.Hostname()) {
		scheme = "http"
	}
	path := u.Path
	if path == "/" {
		path = ""
	}
	brokerURL := scheme + "://" + u.Host + path

	return &ConnectionString{
		RendezvousToken: token,
		PairingSecret:   secret,
		BrokerURL:       brokerURL,
	}, nil
}

// Format renders the connection string form of c. The broker URL is
// used for the host component; its scheme is dropped (the connection
// string scheme itself is rtc2tcp://).
func (c ConnectionString) Format() (string, error) {
	if strings.TrimSpace(c.RendezvousToken) == "" {
		return "", errors.New("rendezvous token is required")
	}
	if strings.TrimSpace(c.PairingSecret) == "" {
		return "", errors.New("pairing secret is required")
	}
	if strings.TrimSpace(c.BrokerURL) == "" {
		return "", errors.New("broker URL is required")
	}
	u, err := url.Parse(c.BrokerURL)
	if err != nil {
		return "", fmt.Errorf("parse broker URL: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("broker URL %q has no host", c.BrokerURL)
	}
	path := u.Path
	if path == "/ws" || path == "/" {
		path = ""
	}
	userInfo := url.UserPassword(c.RendezvousToken, c.PairingSecret)
	return fmt.Sprintf("%s://%s@%s%s",
		ConnectionScheme,
		userInfo.String(),
		u.Host,
		path,
	), nil
}

// RandomToken returns a 128-bit URL-safe random token, suitable for a
// rendezvous_token or a freshly-auto-generated pairing secret.
func RandomToken() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}
