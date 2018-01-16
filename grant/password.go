package grant

import (
	"net/http"

	"strings"

	"github.com/interactive-solutions/go-oauth2"
	"github.com/interactive-solutions/go-oauth2/api"
	"github.com/interactive-solutions/go-oauth2/model"
)

type passwordGrant struct {
	tokenService oauth2.TokenService
}

func NewPasswordGrant(tokenService oauth2.TokenService) OauthGrant {
	return &passwordGrant{
		tokenService: tokenService,
	}
}

func (grant *passwordGrant) GetType() oauth2.GrantType {
	return oauth2.GrantTypePassword
}

func (grant *passwordGrant) GetResponseType() oauth2.ResponseType {
	return ""
}

func (grant *passwordGrant) AllowPublicClients() bool {
	return true
}

func (grant *passwordGrant) CreateAuthorizationResponse(
	w http.ResponseWriter,
	r *http.Request,
	client *model.OauthClient,
	owner *model.OauthTokenOwner,
) {
	api.WriteErrorResponse(w, oauth2.InvalidRequestErr, "Password grant does not support authorization")
}

func (grant *passwordGrant) CreateTokenResponse(w http.ResponseWriter, r *http.Request, client *model.OauthClient, owner *model.OauthTokenOwner) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	scope := r.FormValue("scope")
	scopes := strings.Split(scope, " ")

	if username == "" || password == "" {
		api.WriteErrorResponse(w, oauth2.InvalidRequestErr, "Username and/or password is missing")
		return
	}

	accessToken, err := grant.tokenService.CreateAccessToken(owner, client, scopes)
}
