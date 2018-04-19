package grant

import (
	"net/http"
	"strings"

	"github.com/interactive-solutions/go-oauth2"
)

type PasswordAuthorizationHandler func(username, password string) (oauth2.OauthTokenOwnerId, error)

func NewPasswordGrant(server oauth2.Server, handler PasswordAuthorizationHandler, config PasswordGrantConfig) oauth2.OauthGrant {
	return &passwordGrant{
		server:  server,
		handler: handler,
		config:  config,
	}
}

type passwordGrant struct {
	server  oauth2.Server
	handler PasswordAuthorizationHandler
	config  PasswordGrantConfig
}

func (grant *passwordGrant) CreateAuthorizationCode(r *http.Request, clientId string) (*oauth2.AuthorizationCode, error) {
	return nil, oauth2.NewError(oauth2.InvalidRequestErr, "Password grant does not support authorization")
}

func (grant *passwordGrant) CreateTokens(r *http.Request, clientId string) (*oauth2.AccessToken, *oauth2.RefreshToken, error) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	scopes := strings.Split(r.FormValue("scope"), " ")

	if username == "" || password == "" {
		return nil, nil, oauth2.NewError(oauth2.InvalidRequestErr, "Missing username and/or password")
	}

	if err := grant.server.CallbackPreGrant(username, r.RemoteAddr); err != nil {
		return nil, nil, err
	}

	if grant.handler == nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Password grant not configured correctly")
	}

	tokenOwnerId, err := grant.handler(username, password)
	if err != nil {
		// Empty token signals a failed authentication attempt
		grant.server.CallbackPostGrant(username, grant.server.GetRemoteAddr(r), "")

		return nil, nil, err
	}

	var accessToken *oauth2.AccessToken
	var refreshToken *oauth2.RefreshToken

	// Generate access token until it is unique
	accessToken, err = grant.server.CreateAccessToken(clientId, tokenOwnerId, grant.config.AccessTokenDuration, scopes)
	if err != nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
	}

	// Should we also generate a refresh token
	if grant.config.GenerateRefreshToken {
		refreshToken, err = grant.server.CreateRefreshToken(clientId, tokenOwnerId, grant.config.RefreshTokenDuration, scopes)
		if err != nil {
			return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
		}
	}

	// Callback with a valid token signals a successful login
	grant.server.CallbackPostGrant(username, grant.server.GetRemoteAddr(r), accessToken.Token)

	return accessToken, refreshToken, nil
}

func (grant *passwordGrant) AllowPublicClients() bool {
	return true
}
