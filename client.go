package oauth2

import "github.com/interactive-solutions/go-oauth2/model"

type ClientRepository interface {
	GetById(id string) (*model.OauthClient, error)
	Create(client *model.OauthClient) error
}

type ClientService interface {
	CreateClient(name string, redirectUris []string) (string, string, error)
	GetClientById(id string) (*model.OauthClient, error)
}
