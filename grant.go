package oauth2

import (
	"net/http"
)

type ResponseType string

const (
	ResponseTypeCode  = "code"
	ResponseTypeToken = "token"
)

type GrantType string

const (
	GrantTypePassword          = "password"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
)

type OauthGrant interface {
	CreateAuthorizationCode(r *http.Request, clientId string) (*AuthorizationCode, error)
	CreateTokens(r *http.Request, clientId string) (*AccessToken, *RefreshToken, error)
	AllowPublicClients() bool
}
