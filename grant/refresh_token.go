package grant

import (
	"net/http"

	"strings"

	"github.com/interactive-solutions/go-oauth2"
)

type refreshTokenGrant struct {
	Config          RefreshTokenGrantConfig
	TokenRepository oauth2.TokenRepository
}

func NewRefreshTokenGrant(tokenRepository oauth2.TokenRepository, config RefreshTokenGrantConfig) oauth2.OauthGrant {
	return &refreshTokenGrant{
		TokenRepository: tokenRepository,
		Config:          config,
	}
}

func (grant *refreshTokenGrant) CreateAuthorizationCode(r *http.Request, clientId string) (*oauth2.AuthorizationCode, error) {
	return nil, oauth2.NewError(oauth2.InvalidRequestErr, "Password grant does not support authorization")
}

func (grant *refreshTokenGrant) CreateTokens(r *http.Request, clientId string) (*oauth2.AccessToken, *oauth2.RefreshToken, error) {
	providedToken := r.FormValue("refresh_token")
	scopes := strings.Split(r.FormValue("scope"), " ")

	if providedToken == "" {
		return nil, nil, oauth2.NewError(oauth2.InvalidRequestErr, "Missing refresh token")
	}

	if grant.TokenRepository == nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Refresh token grant not configured correctly")
	}

	// Retrieve refresh token from repository
	refreshToken, err := grant.TokenRepository.GetRefreshToken(providedToken)
	if err != nil {
		return nil, nil, err
	}

	// Validate refresh token
	if refreshToken.IsExpired() {
		return nil, nil, oauth2.NewError(oauth2.InvalidGrantErr, "Refresh token has expired")
	}

	if !refreshToken.MatchScopes(scopes) {
		return nil, nil, oauth2.NewError(oauth2.InvalidScopeErr, "The scope of the new access token exceeds the scope(s) of the refresh token")
	}

	var accessToken *oauth2.AccessToken

	// Generate access token until it is unique
	for {
		accessToken = oauth2.NewAccessToken(clientId, refreshToken.OwnerId, grant.Config.AccessTokenDuration, scopes)

		if t, _ := grant.TokenRepository.GetAccessToken(accessToken.Token); t == nil {
			break
		}
	}

	if err = grant.TokenRepository.CreateAccessToken(accessToken); err != nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
	}

	// Should we generate a new refresh token ?
	if !grant.Config.RotateRefreshTokens {
		return accessToken, refreshToken, nil
	}

	var newRefreshToken *oauth2.RefreshToken

	for {
		// Refresh grant and rotating refresh tokens
		newRefreshToken = oauth2.NewRefreshToken(clientId, refreshToken.OwnerId, grant.Config.RefreshTokenDuration, scopes)

		if t, _ := grant.TokenRepository.GetRefreshToken(newRefreshToken.Token); t == nil {
			break
		}
	}

	if err = grant.TokenRepository.CreateRefreshToken(newRefreshToken); err != nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
	}

	// Should we delete the old refresh token ?
	if grant.Config.RevokeRotatedRefreshTokens {
		if err = grant.TokenRepository.DeleteRefreshToken(refreshToken.Token); err != nil {
			return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
		}
	}

	return accessToken, newRefreshToken, nil
}

func (grant *refreshTokenGrant) AllowPublicClients() bool {
	return true
}
