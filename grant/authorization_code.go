package grant

import (
	"net/http"

	"github.com/interactive-solutions/go-oauth2"
)

type authorizationCodeGrant struct {
}

func NewAuthorizationCodeGrant() oauth2.OauthGrant {
	return &authorizationCodeGrant{}
}

func (grant *authorizationCodeGrant) CreateAuthorizationCode(r *http.Request, clientId string) (*oauth2.AuthorizationCode, error) {
	panic("not implemented")
}

func (grant *authorizationCodeGrant) CreateTokens(r *http.Request, clientId string) (*oauth2.AccessToken, *oauth2.RefreshToken, oauth2.TokenMeta, error) {
	panic("not implemented")
}

func (grant *authorizationCodeGrant) AllowPublicClients() bool {
	return true
}
