package oauth2

import (
	"context"
	"net/http"
	"time"
)

type CallbackPreGrant func(identifier, ipAddr string) error
type CallbackPostGrant func(identifier, ipAddr, token string)
type CallbackPrePersistAccessToken func(accessToken *AccessToken) error
type CallbackPrePersistRefreshToken func(refreshToken *RefreshToken) error

type Server interface {
	// PeriodicallyDeleteExpiredTokens
	PeriodicallyDeleteExpiredTokens(ctx context.Context, interval time.Duration)

	// CreateAccessToken
	CreateAccessToken(clientId string, owner OauthTokenOwnerId, duration time.Duration, scopes []string) (*AccessToken, error)

	// CreateRefreshToken
	CreateRefreshToken(clientId string, owner OauthTokenOwnerId, duration time.Duration, scopes []string) (*RefreshToken, error)

	// CallbackPreGrant is called before any grant is executed with an extracted identifier from the request
	CallbackPreGrant(identifier, ipAddr string) error

	// CallbackPostGrant is called after the grant has been executed with the result of the authentication
	// If the token is provided one the authentication MUST have been successful
	CallbackPostGrant(identifier, ipAddr, token string)

	// CallbackPrePersistAccessToken is called before an access token is persisted to token storage
	// Allows an opportunity to modify an access token before it's persisted to storage
	CallbackPrePersistAccessToken(accessToken *AccessToken) error

	// CallbackPrePersistRefreshToken is called before a refresh token is persisted to token storage
	// Allows an opportunity to modify a refresh token before it's persisted to storage
	CallbackPrePersistRefreshToken(refreshToken *RefreshToken) error

	// HandleTokenRequest usually listens to /oauth/token
	HandleTokenRequest(w http.ResponseWriter, r *http.Request)

	// HandleAuthorizationRequest usually listens /oauth/authorize
	HandleAuthorizationRequest(w http.ResponseWriter, r *http.Request)

	// GetRemoteAddr gets the remote ip address from the request
	GetRemoteAddr(r *http.Request) string
}
