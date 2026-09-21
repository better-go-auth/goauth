package util

import (
	"crypto/rand"
	"math/big"
)

const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GenerateRandomString generates a cryptographically secure random alphanumeric string
func GenerateRandomString(length int) string {
	result := make([]byte, length)
	charLen := big.NewInt(int64(len(characters)))
	for i := range length {
		num, err := rand.Int(rand.Reader, charLen)
		if err != nil {
			result[i] = characters[i%len(characters)]
			continue
		}
		result[i] = characters[num.Int64()]
	}
	return string(result)
}
