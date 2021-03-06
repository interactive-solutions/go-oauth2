package grant

import (
	"net/http"
	"strings"

	"github.com/interactive-solutions/go-oauth2"
)

type refreshTokenGrant struct {
	config     RefreshTokenGrantConfig
	server     oauth2.Server
	repository oauth2.TokenRepository
}

func NewRefreshTokenGrant(server oauth2.Server, repository oauth2.TokenRepository, config RefreshTokenGrantConfig) oauth2.OauthGrant {
	return &refreshTokenGrant{
		config:     config,
		server:     server,
		repository: repository,
	}
}

func (grant *refreshTokenGrant) CreateAuthorizationCode(r *http.Request, clientId string) (*oauth2.AuthorizationCode, error) {
	return nil, oauth2.NewError(oauth2.InvalidRequestErr, "Password grant does not support authorization")
}

func (grant *refreshTokenGrant) CreateTokens(r *http.Request, clientId string) (*oauth2.AccessToken, *oauth2.RefreshToken, oauth2.TokenMeta, error) {
	providedToken := r.FormValue("refresh_token")

	scopes := make([]string, 0)
	if providedScopes := r.FormValue("scope"); providedScopes != "" {
		scopes = strings.Split(providedScopes, " ")
	}

	if providedToken == "" {
		return nil, nil, nil, oauth2.NewError(oauth2.InvalidRequestErr, "Missing refresh token")
	}

	// Retrieve refresh token from repository
	refreshToken, err := grant.repository.GetRefreshToken(providedToken)
	if err != nil {
		return nil, nil, nil, err
	}

	// Validate refresh token
	if refreshToken.IsExpired() {
		return nil, nil, nil, oauth2.NewError(oauth2.InvalidGrantErr, "Refresh token has expired")
	}

	if !refreshToken.MatchScopes(scopes) {
		return nil, nil, nil, oauth2.NewError(oauth2.InvalidScopeErr, "The scope of the new access token exceeds the scope(s) of the refresh token")
	}

	var accessToken *oauth2.AccessToken
	var newRefreshToken *oauth2.RefreshToken

	// Generate access token until it is unique
	accessToken, err = grant.server.CreateAccessToken(clientId, refreshToken.OwnerId, grant.config.AccessTokenDuration, scopes)
	if err != nil {
		return nil, nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
	}

	// Return current refresh token if we're not generating a new one
	if !grant.config.RotateRefreshTokens {
		return accessToken, refreshToken, nil, nil
	}

	// Should we also generate a refresh token
	refreshToken, err = grant.server.CreateRefreshToken(clientId, refreshToken.OwnerId, grant.config.RefreshTokenDuration, scopes)
	if err != nil {
		return nil, nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
	}

	// Should we delete the old refresh token ?
	if grant.config.RevokeRotatedRefreshTokens {
		if err = grant.repository.DeleteRefreshToken(refreshToken.Token); err != nil {
			return nil, nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
		}
	}

	return accessToken, newRefreshToken, nil, nil
}

func (grant *refreshTokenGrant) AllowPublicClients() bool {
	return true
}
