package server

import (
	"time"

	"github.com/interactive-solutions/go-oauth2"
	"github.com/interactive-solutions/go-oauth2/grant"
)

// todo: implement this

var (
	ServerDefaultConfig = ServerConfig{
		AuthorizationCodeDuration: time.Minute * 2,
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      time.Hour * 24,
		Grants: map[oauth2.GrantType]oauth2.OauthGrant{
			oauth2.GrantTypePassword:     grant.NewPasswordGrant(nil),
			oauth2.GrantTypeRefreshToken: grant.NewRefreshTokenGrant(nil),
		},
		ErrorMap: map[error]oauth2.OauthError{
			oauth2.RefreshTokenNotFoundErr: {
				Err:         oauth2.InvalidGrantErr,
				Description: "Refresh has expired or been deleted",
			},
		},
	}
)

type ServerConfig struct {
	// Durations before code / token expires
	AuthorizationCodeDuration time.Duration
	AccessTokenDuration       time.Duration
	RefreshTokenDuration      time.Duration

	// Grants
	Grants map[oauth2.GrantType]oauth2.OauthGrant

	// Authorize the client
	ClientAuthorizedHandler func(clientId, clientSecret string) (bool, error)

	// Error map
	ErrorMap map[error]oauth2.OauthError

	// Should a new refresh token be generated when refresh_token grant is used
	RotateRefreshTokens bool

	// Should the old refresh token be revoked if the refresh token rotated
	RevokeRotatedRefreshTokens bool

	// Should we generate a refresh token for each access token ?
	GenerateRefreshToken bool
}
