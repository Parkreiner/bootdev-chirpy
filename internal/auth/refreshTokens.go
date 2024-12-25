package auth

import (
	"crypto/rand"
	"encoding/hex"
)

func MakeRefreshToken() (string, error) {
	// rand.Read does not do appends, so it's safe to initialize with a length
	// instead of a capacity
	mutableBytes := make([]byte, 256)
	_, err := rand.Read(mutableBytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(mutableBytes), nil
}
