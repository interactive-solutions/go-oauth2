package token

import (
	"time"

	"github.com/interactive-solutions/go-oauth2"
)

type OauthAccessToken struct {
	*oauth2.OauthToken
}

func NewOauthAccessToken(
	client *oauth2.OauthClient,
	owner oauth2.OauthTokenOwner,
	duration time.Duration,
	scopes []string,
) (*OauthAccessToken, error) {
	oauthToken, err := oauth2.NewOauthToken(client, owner, duration, scopes)
	if err != nil {
		return nil, err
	}

	return &OauthAccessToken{OauthToken: oauthToken}, nil
}

type OauthRefreshToken struct {
	*oauth2.OauthToken
}

func NewOauthRefreshToken(
	client *oauth2.OauthClient,
	owner oauth2.OauthTokenOwner,
	duration time.Duration,
	scopes []string,
) (*OauthRefreshToken, error) {
	oauthToken, err := oauth2.NewOauthToken(client, owner, duration, scopes)
	if err != nil {
		return nil, err
	}

	return &OauthRefreshToken{OauthToken: oauthToken}, nil
}
