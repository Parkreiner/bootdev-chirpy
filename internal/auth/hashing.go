package auth

import "golang.org/x/crypto/bcrypt"

func HashPassword(input string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(input), 10)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

func CheckPasswordHash(plaintextPw string, hashedPw string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPw), []byte(plaintextPw))
}
