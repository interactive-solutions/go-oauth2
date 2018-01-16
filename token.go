package oauth2

import "github.com/interactive-solutions/go-oauth2/model"

// The token service is responsible for storing, deleting and retrieving access token
type TokenService interface {
	// Create a new access token and persist it to storage
	CreateAccessToken(owner *model.OauthTokenOwner, client *model.OauthClient, scopes []string) (*model.OauthAccessToken, error)
	// Create a new refresh token and persist it to storage
	CreateRefreshToken(owner *model.OauthTokenOwner, client *model.OauthClient, scopes []string) (*model.OauthRefreshToken, error)
	// Return an access token by its token
	GetAccessTokenByToken(token string) (*model.OauthAccessToken, error)
	// Return a refresh token by its token
	GetRefreshTokenByToken(token string) (*model.OauthRefreshToken, error)
	// Delete an access token by its token
	DeleteAccessTokenByToken(token string) error
	// Delete a refresh token by its token
	DeleteRefreshTokenByToken(token string) error
}
