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
func newOauthToken(clientId string, ownerId OauthTokenOwnerId, duration time.Duration, scopes []string) *OauthToken {
	oauthToken := GenerateRandomString(32)

	return &OauthToken{
		Token:     oauthToken,
		ClientId:  clientId,
		OwnerId:   ownerId,
		ExpiresAt: time.Now().Add(duration),
		Scopes:    scopes,
	}
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

type AccessToken struct {
	*OauthToken

	// Postgres
	TableName struct{} `sql:"oauth_access_tokens"`

	Meta TokenMeta `sql:"-"`
}

func NewAccessToken(
	clientId string,
	ownerId OauthTokenOwnerId,
	duration time.Duration,
	scopes []string,
) *AccessToken {
	return &AccessToken{OauthToken: newOauthToken(clientId, ownerId, duration, scopes)}
}

type RefreshToken struct {
	*OauthToken

	// Postgres
	TableName struct{} `sql:"oauth_refresh_tokens"`
}

func NewRefreshToken(
	clientId string,
	ownerId OauthTokenOwnerId,
	duration time.Duration,
	scopes []string,
) *RefreshToken {
	return &RefreshToken{OauthToken: newOauthToken(clientId, ownerId, duration, scopes)}
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
) *AuthorizationCode {
	return &AuthorizationCode{OauthToken: newOauthToken(clientId, ownerId, duration, scopes), RedirectUri: redirectUri}
}

type TokenRepository interface {
	CreateAccessToken(token *AccessToken) error
	CreateRefreshToken(token *RefreshToken) error

	GetAccessToken(token string) (*AccessToken, error)
	GetRefreshToken(token string) (*RefreshToken, error)

	DeleteAccessToken(token string) error
	DeleteRefreshToken(token string) error
	DeleteExpiredAccessTokens() error
	DeleteExpiredRefreshTokens() error
}

type TokenMeta map[string]interface{}
