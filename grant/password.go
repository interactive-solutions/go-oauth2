package grant

import (
	"net/http"

	"strings"

	"github.com/interactive-solutions/go-oauth2"
)

type PasswordAuthorizationHandler func(username, password string) (oauth2.OauthTokenOwnerId, error)

type passwordGrant struct {
	Handler         PasswordAuthorizationHandler
	TokenRepository oauth2.TokenRepository
	Config          PasswordGrantConfig
}

func NewPasswordGrant(
	handler PasswordAuthorizationHandler,
	tokenRepository oauth2.TokenRepository,
	config PasswordGrantConfig,
) oauth2.OauthGrant {
	return &passwordGrant{
		Handler:         handler,
		TokenRepository: tokenRepository,
		Config:          config,
	}
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

	if grant.Handler == nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Password grant not configured correctly")
	}

	tokenOwnerId, err := grant.Handler(username, password)
	if err != nil {
		return nil, nil, err
	}

	var accessToken *oauth2.AccessToken
	var refreshToken *oauth2.RefreshToken

	// Generate access token until it is unique
	for {
		accessToken = oauth2.NewAccessToken(clientId, tokenOwnerId, grant.Config.AccessTokenDuration, scopes)

		if t, _ := grant.TokenRepository.GetAccessToken(accessToken.Token); t == nil {
			break
		}
	}

	if err = grant.TokenRepository.CreateAccessToken(accessToken); err != nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
	}

	// Should we also generate a refresh token
	if grant.Config.GenerateRefreshToken {
		// Generate a refresh token until it is unique
		for {
			refreshToken = oauth2.NewRefreshToken(clientId, tokenOwnerId, grant.Config.RefreshTokenDuration, scopes)

			if t, _ := grant.TokenRepository.GetRefreshToken(refreshToken.Token); t == nil {
				break
			}
		}

		if err = grant.TokenRepository.CreateRefreshToken(refreshToken); err != nil {
			return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
		}
	}

	return accessToken, refreshToken, nil
}

func (grant *passwordGrant) AllowPublicClients() bool {
	return true
}
