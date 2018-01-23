package oauth2

import (
	"net/http"
)

type GrantType string

const (
	GrantTypePassword          = "password"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
)

type OauthGrant interface {
	Authorize(r *http.Request, clientId, clientSecret string) (OauthTokenOwnerId, error)
	AllowPublicClients() bool
}
