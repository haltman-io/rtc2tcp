package rendezvous

import (
	"errors"
	"fmt"
	"strings"
)

const maxTokenLength = 128

func ValidateToken(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("rendezvous token is required")
	}
	if len(token) > maxTokenLength {
		return "", fmt.Errorf("rendezvous token exceeds %d bytes", maxTokenLength)
	}
	for _, r := range token {
		if r < 0x21 || r > 0x7e {
			return "", errors.New("rendezvous token must use visible ASCII characters only")
		}
	}
	return token, nil
}
