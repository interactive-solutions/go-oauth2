package token

import (
	"time"

	"github.com/interactive-solutions/go-oauth2"
)

type AuthorizationCode struct {
	*oauth2.OauthToken

	RedirectUri string
}

func NewAuthorizationCode(
	client *oauth2.OauthClient,
	owner oauth2.OauthTokenOwner,
	duration time.Duration,
	scopes []string,
	redirectUri string,
) (*AuthorizationCode, error) {
	oauthToken, err := oauth2.NewOauthToken(client, owner, duration, scopes)
	if err != nil {
		return nil, err
	}

	return &AuthorizationCode{OauthToken: oauthToken, RedirectUri: redirectUri}, nil
}
