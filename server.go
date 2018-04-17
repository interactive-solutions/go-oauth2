package oauth2

import (
	"context"
	"net/http"
	"time"
)

type CallbackPreGrant func(identifier, ipAddr string) error
type CallbackPostGrant func(identifier, ipAddr, token string)

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
	// If the token is provided one the authentication MUST have been successfull
	CallbackPostGrant(identifier, ipAddr, token string)

	// HandleTokenRequest usually listens to /oauth/token
	HandleTokenRequest(w http.ResponseWriter, r *http.Request)

	// HandleAuthorizationRequest usually listens /oauth/authorize
	HandleAuthorizationRequest(w http.ResponseWriter, r *http.Request)
}
