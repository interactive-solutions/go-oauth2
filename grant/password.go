package grant

import (
	"net/http"

	"strings"

	"github.com/interactive-solutions/go-oauth2"
	"github.com/interactive-solutions/go-oauth2/token"
)

// Callable that is used to verify the username and password
type ValidateUserCredentialsCallback func(username, password string) (oauth2.OauthTokenOwner, *oauth2.OauthError)

type passwordGrant struct {
	config                PasswordGrantConfig
	authorizationCallback ValidateUserCredentialsCallback
	tokenService          oauth2.TokenService
}

func NewPasswordGrant(
	config PasswordGrantConfig,
	callback ValidateUserCredentialsCallback,
	tokenService oauth2.TokenService,
) oauth2.OauthGrant {
	return &passwordGrant{
		config:                config,
		authorizationCallback: callback,
		tokenService:          tokenService,
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

func (grant *passwordGrant) CreateAuthorizationCode(
	r *http.Request,
	client *oauth2.OauthClient,
	owner *oauth2.OauthTokenOwner,
) (*token.AuthorizationCode, *oauth2.OauthError) {
	return nil, oauth2.NewError(oauth2.InvalidRequestErr, "Password grant does not support authorization")
}

func (grant *passwordGrant) CreateToken(
	r *http.Request,
	client *oauth2.OauthClient,
	owner oauth2.OauthTokenOwner,
) (*token.OauthAccessToken, *token.OauthRefreshToken, *oauth2.OauthError) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	scope := r.FormValue("scope")
	scopes := strings.Split(scope, " ")

	if username == "" || password == "" {
		return nil, nil, oauth2.NewError(oauth2.InvalidRequestErr, "Username and/or password is missing")
	}

	if grant.authorizationCallback == nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Password grant missing authorization callback")
	}

	owner, err := grant.authorizationCallback(username, password)
	if err != nil {
		return nil, nil, err
	}

	accessToken, err := grant.tokenService.CreateAccessToken(owner, client, scopes)
	if err != nil {
		return nil, nil, err
	}

	// Should we generate a refresh token ?
	if grant.config.GenerateRefreshToken {
		if refreshToken, err := grant.tokenService.CreateRefreshToken(owner, client, scopes); err == nil {
			return accessToken, refreshToken, nil
		}

		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Error when creating refresh token")
	}

	return accessToken, nil, nil
}
