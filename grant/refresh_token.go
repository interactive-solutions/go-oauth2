package grant

import (
	"net/http"

	"github.com/interactive-solutions/go-oauth2"
)

type refreshTokenGrant struct {
	TokenRepository oauth2.TokenRepository
}

func NewRefreshTokenGrant(tokenRepository oauth2.TokenRepository) oauth2.OauthGrant {
	return &refreshTokenGrant{tokenRepository}
}

func (grant *refreshTokenGrant) Authorize(r *http.Request, clientId, clientSecret string) (oauth2.OauthTokenOwnerId, error) {
	providedToken := r.FormValue("refresh_token")
	if providedToken == "" {
		return "", oauth2.NewError(oauth2.InvalidRequestErr, "Missing refresh token")
	}

	if grant.TokenRepository == nil {
		return "", oauth2.NewError(oauth2.InvalidGrantErr, "Refresh token has expired or been deleted")
	}

	refreshToken, err := grant.TokenRepository.GetRefreshToken(providedToken)
	if err != nil {
		return "", err
	}

	return refreshToken.OwnerId, nil
}

func (grant *refreshTokenGrant) AllowPublicClients() bool {
	return true
}
