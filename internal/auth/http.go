package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func GetBearerToken(headers *http.Header) (string, error) {
	rawBearer := headers.Get("Authorization")
	if rawBearer == "" {
		return "", errors.New("missing Authorization header")
	}

	prefix, token, ok := strings.Cut(rawBearer, " ")
	if !ok || prefix != "Bearer" {
		return "", fmt.Errorf("token '%s' is not in the correct format", rawBearer)
	}

	return strings.TrimSpace(token), nil
}

func GetApiKey(headers *http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing Authorization header")
	}

	prefix, key, ok := strings.Cut(authHeader, " ")
	if !ok || prefix != "ApiKey" {
		return "", errors.New("received API key in unknown format")
	}

	return key, nil
}
