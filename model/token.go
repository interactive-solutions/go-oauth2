package model

import (
	"time"
)

type OauthAccessToken struct {
	*OauthToken
}

func NewOauthAccessToken(client *OauthClient, owner OauthTokenOwner, duration time.Duration, scopes []string) (*OauthAccessToken, error) {
	oauthToken, err := newOauthToken(client, owner, duration, scopes)
	if err != nil {
		return nil, err
	}

	return &OauthAccessToken{oauthToken}, nil
}

type OauthRefreshToken struct {
	*OauthToken
}

func NewOauthRefreshToken(client *OauthClient, owner OauthTokenOwner, duration time.Duration, scopes []string) (*OauthRefreshToken, error) {
	oauthToken, err := newOauthToken(client, owner, duration, scopes)
	if err != nil {
		return nil, err
	}

	return &OauthRefreshToken{oauthToken}, nil
}
