package oauth2

import (
	"time"
)

type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
)

type OauthTokenOwnerId string

type OauthToken struct {
	Token     string `sql:",pk"`
	ExpiresAt time.Time
	Scopes    []string `pg:",array"`
	ClientId  string
	OwnerId   OauthTokenOwnerId
}

// Creates an abstract oauth token, SHOULD ONLY be called when creating another token
func newOauthToken(clientId string, ownerId OauthTokenOwnerId, duration time.Duration, scopes []string) (*OauthToken, error) {
	oauthToken, err := GenerateRandomString(20)
	if err != nil {
		return nil, err
	}

	return &OauthToken{
		Token:     oauthToken,
		ClientId:  clientId,
		OwnerId:   ownerId,
		ExpiresAt: time.Now().Add(duration),
		Scopes:    scopes,
	}, nil
}

func (token *OauthToken) GetExpiresIn() float64 {
	return time.Until(token.ExpiresAt).Seconds()
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

type OauthAccessToken struct {
	*OauthToken

	// Postgres
	TableName struct{} `sql:"oauth_access_tokens"`
}

func NewOauthAccessToken(
	clientId string,
	ownerId OauthTokenOwnerId,
	duration time.Duration,
	scopes []string,
) (*OauthAccessToken, error) {
	oauthToken, err := newOauthToken(clientId, ownerId, duration, scopes)
	if err != nil {
		return nil, err
	}

	return &OauthAccessToken{OauthToken: oauthToken}, nil
}

type OauthRefreshToken struct {
	*OauthToken

	// Postgres
	TableName struct{} `sql:"oauth_refresh_tokens"`
}

func NewOauthRefreshToken(
	clientId string,
	ownerId OauthTokenOwnerId,
	duration time.Duration,
	scopes []string,
) (*OauthRefreshToken, error) {
	oauthToken, err := newOauthToken(clientId, ownerId, duration, scopes)
	if err != nil {
		return nil, err
	}

	return &OauthRefreshToken{OauthToken: oauthToken}, nil
}

type AuthorizationCode struct {
	*OauthToken

	// Postgres
	TableName struct{} `json:"oauth_authorization_codes"`

	RedirectUri string
}

func NewAuthorizationCode(
	clientId string,
	ownerId OauthTokenOwnerId,
	duration time.Duration,
	scopes []string,
	redirectUri string,
) (*AuthorizationCode, error) {
	oauthToken, err := newOauthToken(clientId, ownerId, duration, scopes)
	if err != nil {
		return nil, err
	}

	return &AuthorizationCode{OauthToken: oauthToken, RedirectUri: redirectUri}, nil
}

type TokenRepository interface {
	CreateAccessToken(token *OauthAccessToken) error
	CreateRefreshToken(token *OauthRefreshToken) error

	GetAccessToken(token string) (*OauthAccessToken, error)
	GetRefreshToken(token string) (*OauthRefreshToken, error)

	DeleteAccessToken(token string) error
	DeleteRefreshToken(token string) error
	DeleteExpiredAccessTokens() error
	DeleteExpiredRefreshTokens() error
}
