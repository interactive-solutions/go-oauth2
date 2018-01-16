package model

import "time"

type AuthorizationCode struct {
	*OauthToken

	RedirectUri string
}

func NewAuthorizationCode(client *OauthClient, owner OauthTokenOwner, duration time.Duration, scopes []string, redirectUri string) (*AuthorizationCode, error) {
	oauthToken, err := newOauthToken(client, owner, duration, scopes)
	if err != nil {
		return nil, err
	}

	return &AuthorizationCode{OauthToken: oauthToken, RedirectUri: redirectUri}, nil
}
