package grant

import (
	"net/http"

	"github.com/interactive-solutions/go-oauth2"
)

type PasswordAuthorizationHandler func(username, password string) (oauth2.OauthTokenOwnerId, error)

type passwordGrant struct {
	Handler PasswordAuthorizationHandler
}

func NewPasswordGrant(handler PasswordAuthorizationHandler) oauth2.OauthGrant {
	return &passwordGrant{handler}
}

func (grant *passwordGrant) Authorize(r *http.Request, clientId, clientSecret string) (oauth2.OauthTokenOwnerId, error) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		return "", oauth2.NewError(oauth2.InvalidRequestErr, "Missing username and/or password")
	}

	if grant.Handler == nil {
		return "", oauth2.NewError(oauth2.AccessDeniedErr, "Invalid credentials provided")
	}

	return grant.Handler(username, password)
}

func (grant *passwordGrant) AllowPublicClients() bool {
	return true
}
