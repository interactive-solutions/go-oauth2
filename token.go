package oauth2

import (
	"time"

	"github.com/interactive-solutions/go-oauth2/token"
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

// Creates an abstract oauth token, SHOULD ONLY be called when creating another token
func NewOauthToken(client *OauthClient, owner OauthTokenOwner, duration time.Duration, scopes []string) (*OauthToken, error) {
	token, err := GenerateRandomString(20)
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

// The token service is responsible for storing, deleting and retrieving access token
type TokenService interface {
	// Create a new access token and persist it to storage
	CreateAccessToken(owner OauthTokenOwner, client *OauthClient, scopes []string) (*token.OauthAccessToken, *OauthError)
	// Create a new refresh token and persist it to storage
	CreateRefreshToken(owner OauthTokenOwner, client *OauthClient, scopes []string) (*token.OauthRefreshToken, *OauthError)
	// Return an access token by its token
	GetAccessTokenByToken(token string) (*token.OauthAccessToken, *OauthError)
	// Return a refresh token by its token
	GetRefreshTokenByToken(token string) (*token.OauthRefreshToken, *OauthError)
	// Delete an access token by its token
	DeleteAccessTokenByToken(token string) *OauthError
	// Delete a refresh token by its token
	DeleteRefreshTokenByToken(token string) *OauthError
}
