package hasher

import (
	"github.com/matthewhartstonge/argon2"
	"golang.org/x/crypto/bcrypt"
)

// BcryptCreateHash  password
func BcryptCreateHash(password string) (string, error) {
	// Convert password string to byte slice
	passwordBytes := []byte(password)

	// Hash password with Bcrypt's min cost
	hashedPasswordBytes, err := bcrypt.
		GenerateFromPassword(passwordBytes, bcrypt.MinCost)
	return string(hashedPasswordBytes), err
}

func BcryptPasswordsMatch(PlainPassword, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword), []byte(PlainPassword))
	return err == nil
}

// BcryptCreateHash  password
func ArgonCreateHash(password string) (string, error) {
	// Convert password string to byte slice
	passwordBytes := []byte(password)
	argon := argon2.DefaultConfig()
	encoded, err := argon.HashEncoded(passwordBytes)
	if err != nil {
		return "", err
	}
	return string(encoded), err
}

func ArgonPasswordsMatch(PlainPassword, hashedPassword string) bool {
	ok, err := argon2.VerifyEncoded([]byte(PlainPassword), []byte(hashedPassword))
	return err == nil && ok
}
