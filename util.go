package oauth2

import "math/rand"

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateRandomString(length uint) string {
	bytes := make([]byte, length)
	for i := range bytes {
		bytes[i] = letters[rand.Intn(len(letters))]
	}

	return string(bytes)
}
