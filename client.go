package oauth2

import (
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type OauthClient struct {
	Id           string
	Name         string
	Secret       string
	RedirectUris []string
}

func NewOauthClient(name string, redirectUris []string) *OauthClient {
	return &OauthClient{
		Id:           uuid.NewV4().String(),
		Name:         name,
		RedirectUris: redirectUris,
	}
}

func (client *OauthClient) HasRedirectUri(redirectUri string) bool {
	for _, value := range client.RedirectUris {
		if value == redirectUri {
			return true
		}
	}

	return false
}

// Is this a public client
func (client *OauthClient) IsPublic() bool {
	return client.Secret == ""
}

// Authenticate the client
func (client *OauthClient) Authenticate(secret string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(secret)); err == nil {
		return true
	}

	return false
}

// Create a secret for the client
func (client *OauthClient) GenerateSecret() error {
	randomString, err := GenerateRandomString(20)
	if err != nil {
		return err
	}

	secret, err := bcrypt.GenerateFromPassword([]byte(randomString), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	client.Secret = string(secret)

	return nil
}

type ClientRepository interface {
	GetById(id string) (*OauthClient, error)
	Create(client *OauthClient) error
}

type ClientService interface {
	Create(name string, redirectUris []string) (string, string, error)
	GetById(id string) (*OauthClient, error)
}
