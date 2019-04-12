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
	// Create and persist authorization code to storage
	CreateAuthorizationCode(r *http.Request, clientId string) (*AuthorizationCode, error)
	// Create and persist tokens to storage
	CreateTokens(r *http.Request, clientId string) (*AccessToken, *RefreshToken, *TokenMeta, error)
	// Allow public clients ?
	AllowPublicClients() bool
}
