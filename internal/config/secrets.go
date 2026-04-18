package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	EnvRendezvousToken   = "RTC2TCP_RENDEZVOUS_TOKEN"
	EnvPairingSecret     = "RTC2TCP_PAIRING_SECRET"
	EnvPairingSecretFile = "RTC2TCP_PAIRING_SECRET_FILE"
)

func ResolveRendezvousToken(flagValue string) (string, error) {
	if v := ResolveRendezvousTokenOptional(flagValue); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("rendezvous token is required via --rendezvous-token or %s", EnvRendezvousToken)
}

// ResolveRendezvousTokenOptional returns the first non-empty source
// among the explicit flag value and EnvRendezvousToken. Returns ""
// when nothing is set, instead of erroring. Callers that support
// auto-generation use this form.
func ResolveRendezvousTokenOptional(flagValue string) string {
	if value := strings.TrimSpace(flagValue); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv(EnvRendezvousToken))
}

func ResolvePairingSecret(pairingSecret, pairingSecretFile, legacySecret, legacySecretFile string) (string, error) {
	secret, err := ResolvePairingSecretOptional(pairingSecret, pairingSecretFile, legacySecret, legacySecretFile)
	if err != nil {
		return "", err
	}
	if secret == "" {
		return "", fmt.Errorf("pairing secret is required via --pairing-secret-file, --pairing-secret, or %s/%s", EnvPairingSecretFile, EnvPairingSecret)
	}
	return secret, nil
}

// ResolvePairingSecretOptional mirrors ResolvePairingSecret but returns
// an empty string (no error) when no source is provided. Callers that
// support auto-generation use this form. Multiple conflicting sources
// still produce an error, since that is a configuration bug regardless
// of whether auto-generation is on the table.
func ResolvePairingSecretOptional(pairingSecret, pairingSecretFile, legacySecret, legacySecretFile string) (string, error) {
	explicitSources := countNonEmpty(pairingSecret, pairingSecretFile, legacySecret, legacySecretFile)
	if explicitSources > 1 {
		return "", errors.New("use only one explicit pairing secret source")
	}

	envSecret := strings.TrimSpace(os.Getenv(EnvPairingSecret))
	envSecretFile := strings.TrimSpace(os.Getenv(EnvPairingSecretFile))
	if explicitSources == 0 && countNonEmpty(envSecret, envSecretFile) > 1 {
		return "", errors.New("use only one pairing secret environment source")
	}

	for _, source := range []struct {
		value  string
		path   string
		origin string
	}{
		{path: pairingSecretFile, origin: "--pairing-secret-file"},
		{value: pairingSecret, origin: "--pairing-secret"},
		{path: legacySecretFile, origin: "--secret-file"},
		{value: legacySecret, origin: "--secret"},
		{path: envSecretFile, origin: EnvPairingSecretFile},
		{value: envSecret, origin: EnvPairingSecret},
	} {
		if strings.TrimSpace(source.path) != "" {
			secret, err := readSecretFile(source.path)
			if err != nil {
				return "", fmt.Errorf("load pairing secret from %s: %w", source.origin, err)
			}
			return secret, nil
		}
		if strings.TrimSpace(source.value) != "" {
			return strings.TrimSpace(source.value), nil
		}
	}

	return "", nil
}

func readSecretFile(path string) (string, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", errors.New("secret file is empty")
	}
	return secret, nil
}

func countNonEmpty(values ...string) int {
	count := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			count++
		}
	}
	return count
}
