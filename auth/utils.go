package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func hashPassword(pwd string) (string, error) {
	if len(pwd) == 0 {
		return "", errors.New("Empty passowrd was passed")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
