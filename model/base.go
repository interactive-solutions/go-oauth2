package model

import (
	"time"

	"encoding/json"
	"strings"

	oauth2 "github.com/interactive-solutions/go-oauth2"
)

type OauthTokenOwner interface {
	GetId() interface{}
}

type OauthToken struct {
	Token     string
	Client    *OauthClient
	Owner     OauthTokenOwner
	ExpiresAt time.Time
	Scopes    []string
}

func newOauthToken(client *OauthClient, owner OauthTokenOwner, duration time.Duration, scopes []string) (*OauthToken, error) {
	token, err := oauth2.GenerateRandomString(20)
	if err != nil {
		return nil, err
	}

	return &OauthToken{
		Token:     token,
		Client:    client,
		Owner:     owner,
		ExpiresAt: time.Now().Add(duration),
		Scopes:    scopes,
	}, nil
}

func (token *OauthToken) GetExpiresIn() time.Duration {
	return time.Until(token.ExpiresAt)
}

func (token *OauthToken) IsExpired() bool {
	return token.ExpiresAt.Before(time.Now())
}

func (token *OauthToken) MatchScopes(scopes []string) bool {
	for _, scope := range scopes {
		scopeExists := false

		for _, tokenScope := range token.Scopes {
			if scope == tokenScope {
				scopeExists = true
				break
			}
		}

		if !scopeExists {
			return false
		}
	}

	return true
}

func (token *OauthToken) IsValid(scopes []string) bool {
	if token.IsExpired() {
		return false
	}

	if len(scopes) > 0 && !token.MatchScopes(scopes) {
		return false
	}

	return true
}

// Marshal token to expected oauth2 response
func (token *OauthToken) MarshalJSON() ([]byte, error) {
	data := &struct {
		AccessToken string           `json:"access_token"`
		TokenType   oauth2.TokenType `json:"token_type"`
		ExpiresIn   time.Duration    `json:"expires_in"`
		Scope       string           `json:"scope"`
		OwnerId     interface{}      `json:"owner_id,omitempty"`
	}{
		AccessToken: token.Token,
		TokenType:   oauth2.TokenTypeBearer,
		ExpiresIn:   time.Until(token.ExpiresAt),
		Scope:       strings.Join(token.Scopes, " "),
	}

	if token.Owner != nil {
		data.OwnerId = token.Owner.GetId()
	}

	return json.Marshal(data)
}
