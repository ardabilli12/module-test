package basic_crypto

import (
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type BasicAuth struct {
	Email    string
	Password string
}

func New() *BasicAuth {
	return &BasicAuth{}
}

func (b *BasicAuth) Encrypt(email, password string) string {
	dataUser := email + ":" + password
	pwd := []byte(dataUser)

	hashedPassword, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	return string(hashedPassword)
}

func (b *BasicAuth) Decrypt(encrypted string) (string, string, error) {
	parts := strings.SplitN(encrypted, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return "", "", errors.New("invalid authorization header")
	}

	// Decode the base64-encoded credentials
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", errors.New("failed to decode credentials")
	}

	// Split the decoded credentials into the username and password
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return "", "", errors.New("invalid credentials")
	}

	return credentials[0], credentials[1], nil

}
