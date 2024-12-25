package auth

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com.com/Parkreiner/bootdev-chirpy/internal/secret"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const jwtIssuer = "chirpy"

func MakeJWT(
	userId uuid.UUID,
	tokenSecret secret.Secret[string],
	expiresIn time.Duration,
) (string, error) {
	now := time.Now().UTC()
	unsignedToken := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Subject:   userId.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
		},
	)

	// The HS256 standard requires that the key be of type []byte, even though
	// the function signature won't complain if you pass a string in directly
	jwtStr, err := unsignedToken.SignedString(
		[]byte(tokenSecret.DangerouslyRevealSecret()),
	)
	if err != nil {
		return "", err
	}
	return jwtStr, nil
}

func ValidateJwt(
	jwtToken string,
	secret secret.Secret[string],
) (uuid.UUID, error) {
	parsed, err := jwt.ParseWithClaims(
		jwtToken,
		&jwt.RegisteredClaims{},
		func(t *jwt.Token) (any, error) {
			return []byte(secret.DangerouslyRevealSecret()), nil
		},
	)
	if err != nil {
		log.Print("-----", parsed.Claims, "\n\n")
		return uuid.UUID{}, err
	}
	if !parsed.Valid {
		return uuid.UUID{}, errors.New("JWT was successfully parsed but is not valid")
	}

	issuer, err := parsed.Claims.GetIssuer()
	if err != nil {
		return uuid.UUID{}, err
	}
	if issuer != jwtIssuer {
		return uuid.UUID{}, fmt.Errorf("issuer %s from the token is not valid", issuer)
	}

	subject, err := parsed.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, err
	}
	val, err := uuid.Parse(subject)
	if err != nil {
		return uuid.UUID{}, err
	}
	return val, nil
}
