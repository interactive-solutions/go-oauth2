package grant

import (
	"net/http"

	"strings"

	"github.com/interactive-solutions/go-oauth2"
	"github.com/interactive-solutions/go-oauth2/token"
)

type refreshTokenGrant struct {
	config       RefreshTokenGrantConfig
	tokenService oauth2.TokenService
}

func NewRefreshTokenGrant(config RefreshTokenGrantConfig, tokenService oauth2.TokenService) oauth2.OauthGrant {
	return &refreshTokenGrant{
		config:       config,
		tokenService: tokenService,
	}
}

func (grant *refreshTokenGrant) GetType() oauth2.GrantType {
	return oauth2.GrantTypeRefreshToken
}

func (grant *refreshTokenGrant) GetResponseType() oauth2.ResponseType {
	return ""
}

func (grant *refreshTokenGrant) AllowPublicClients() bool {
	return true
}

func (grant *refreshTokenGrant) CreateAuthorizationCode(
	r *http.Request,
	client *oauth2.OauthClient,
	owner *oauth2.OauthTokenOwner,
) (*token.AuthorizationCode, *oauth2.OauthError) {
	return nil, oauth2.NewError(oauth2.InvalidRequestErr, "Refresh token grant does not support authorization")
}

func (grant *refreshTokenGrant) CreateToken(
	r *http.Request,
	client *oauth2.OauthClient,
	owner oauth2.OauthTokenOwner,
) (*token.OauthAccessToken, *token.OauthRefreshToken, *oauth2.OauthError) {
	submittedToken := r.FormValue("refresh_token")
	scope := r.FormValue("scope")
	scopes := strings.Split(scope, " ")

	if submittedToken == "" {
		return nil, nil, oauth2.NewError(oauth2.InvalidRequestErr, "Missing refresh submittedToken")
	}

	refreshToken, err := grant.tokenService.GetRefreshTokenByToken(submittedToken)
	if err != nil {
		return nil, nil, err
	}

	if refreshToken.IsExpired() {
		return nil, nil, oauth2.NewError(oauth2.InvalidGrantErr, "Refresh token has expired")
	}

	if !refreshToken.MatchScopes(scopes) {
		return nil, nil, oauth2.NewError(
			oauth2.InvalidScopeErr,
			"The scope of the new access token exceeds the scope of the refresh token",
		)
	}

	accessToken, err := grant.tokenService.CreateAccessToken(refreshToken.Owner, client, scopes)
	if err != nil {
		return nil, nil, err
	}

	if grant.config.RotateRefreshTokens {
		if grant.config.RevokeRotatedRefreshTokens {
			if err := grant.tokenService.DeleteRefreshTokenByToken(refreshToken.Token); err != nil {
				return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Error when revoking old refresh token")
			}
		}

		refreshToken, oauthErr := grant.tokenService.CreateRefreshToken(refreshToken.Owner, client, scopes)
		if oauthErr != nil {
			return nil, nil, oauthErr
		}

		return accessToken, refreshToken, nil
	}

	return accessToken, refreshToken, nil
}
