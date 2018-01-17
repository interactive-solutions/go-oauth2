package oauth2

import (
	"net/http"

	"github.com/interactive-solutions/go-oauth2/token"
)

type OauthGrant interface {
	// The type of the grant
	GetType() GrantType

	// Response type of grant
	GetResponseType() ResponseType

	// Allow public clients
	AllowPublicClients() bool

	// Handle authorization request
	CreateAuthorizationCode(
		r *http.Request,
		client *OauthClient,
		owner *OauthTokenOwner,
	) (*token.AuthorizationCode, *OauthError)

	// Handle token request
	CreateToken(
		r *http.Request,
		client *OauthClient,
		owner OauthTokenOwner,
	) (*token.OauthAccessToken, *token.OauthRefreshToken, *OauthError)
}
