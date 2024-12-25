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
