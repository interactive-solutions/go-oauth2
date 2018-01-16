package oauth2

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandomString(length uint) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	// Note that err == nil only if we read len(bytes) bytes.
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}
