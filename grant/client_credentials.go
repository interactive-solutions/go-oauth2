package grant

import (
	"net/http"

	"strings"

	"github.com/interactive-solutions/go-oauth2"
)

type clientCredentialsGrant struct {
	TokenRepository oauth2.TokenRepository
	Config          ClientCredentialsGrantConfig
}

func NewClientCredentialsGrant(tokenRepository oauth2.TokenRepository, config ClientCredentialsGrantConfig) oauth2.OauthGrant {
	return &clientCredentialsGrant{
		TokenRepository: tokenRepository,
		Config:          config,
	}
}

func (grant *clientCredentialsGrant) CreateAuthorizationCode(r *http.Request, clientId string) (*oauth2.AuthorizationCode, error) {
	return nil, oauth2.NewError(oauth2.InvalidRequestErr, "Client credentials grant does not support authorization")
}

func (grant *clientCredentialsGrant) CreateTokens(r *http.Request, clientId string) (*oauth2.AccessToken, *oauth2.RefreshToken, oauth2.TokenMeta, error) {
	scopes := make([]string, 0)
	if providedScopes := r.FormValue("scope"); providedScopes != "" {
		scopes = strings.Split(providedScopes, " ")
	}

	var accessToken *oauth2.AccessToken

	// Generate access token until it is unique
	for {
		accessToken = oauth2.NewAccessToken(clientId, "", grant.Config.AccessTokenDuration, scopes)

		if t, _ := grant.TokenRepository.GetAccessToken(accessToken.Token); t == nil {
			break
		}
	}

	if err := grant.TokenRepository.CreateAccessToken(accessToken); err != nil {
		return nil, nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
	}

	return accessToken, nil, nil, nil
}

func (grant *clientCredentialsGrant) AllowPublicClients() bool {
	return false
}
