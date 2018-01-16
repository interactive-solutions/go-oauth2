package grant

import (
	"net/http"

	"github.com/interactive-solutions/go-oauth2"
	"github.com/interactive-solutions/go-oauth2/model"
)

type OauthGrant interface {
	// The type of the grant
	GetType() oauth2.GrantType
	// Response type of grant
	GetResponseType() oauth2.ResponseType
	// Allow public clients
	AllowPublicClients() bool
	// Handle authorization request
	CreateAuthorizationResponse(w http.ResponseWriter, r *http.Request, client *model.OauthClient, owner *model.OauthTokenOwner)
	// Handle token request
	CreateTokenResponse(w http.ResponseWriter, r *http.Request, client *model.OauthClient, owner *model.OauthTokenOwner)
}
